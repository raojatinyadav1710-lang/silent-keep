// SILENT KEEP relay server. Zero dependencies. Run: node server.js
// The server only relays encrypted blobs. It never sees keys, names or text.
// Nothing is stored on disk and nothing is logged.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const FILES = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/style.css': ['style.css', 'text/css; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/arrows.jpg': ['arrows.jpg', 'image/jpeg'],
  '/moon.jpg': ['moon.jpg', 'image/jpeg'],
  '/roses.jpg': ['roses.jpg', 'image/jpeg'],
  '/vigil.jpg': ['vigil.jpg', 'image/jpeg'],
};
const MAX_BODY = 64 * 1024;
const MAX_PER_ROOM = 20;
const RATE_PER_MIN = 120;

const rooms = new Map(); // roomId -> Map(cid -> res)
const hits = new Map();  // ip -> {n, t} (memory only)

const hashes = {};
for (const [url, [file]] of Object.entries(FILES)) {
  hashes[file] = crypto.createHash('sha256').update(fs.readFileSync(path.join(__dirname, file))).digest('hex');
}

const SEC = {
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cache-Control': 'no-store',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
};

function limited(req) {
  const ip = req.socket.remoteAddress;
  const now = Date.now();
  const h = hits.get(ip);
  if (!h || now - h.t > 60000) { hits.set(ip, { n: 1, t: now }); return false; }
  return ++h.n > RATE_PER_MIN;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (now - v.t > 60000) hits.delete(k); }, 60000).unref();

const ID = /^[a-f0-9]{64}$/;
const CID = /^[a-zA-Z0-9_-]{8,32}$/;

http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');

  if (req.method === 'GET' && FILES[url.pathname]) {
    const [file, type] = FILES[url.pathname];
    res.writeHead(200, { ...SEC, 'Content-Type': type });
    return res.end(fs.readFileSync(path.join(__dirname, file)));
  }

  if (req.method === 'GET' && url.pathname === '/integrity') {
    res.writeHead(200, { ...SEC, 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(hashes, null, 2));
  }

  if (limited(req)) { res.writeHead(429, SEC); return res.end(); }

  const room = url.searchParams.get('room') || '';
  const cid = url.searchParams.get('cid') || '';
  if (!ID.test(room) || !CID.test(cid)) { res.writeHead(400, SEC); return res.end(); }

  if (req.method === 'GET' && url.pathname === '/events') {
    let members = rooms.get(room);
    if (!members) rooms.set(room, (members = new Map()));
    if (members.size >= MAX_PER_ROOM) { res.writeHead(403, SEC); return res.end(); }
    res.writeHead(200, { ...SEC, 'Content-Type': 'text/event-stream', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
    res.write('retry: 2000\n\n');
    members.set(cid, res);
    const beat = setInterval(() => res.write(': \n\n'), 25000);
    req.on('close', () => {
      clearInterval(beat);
      members.delete(cid);
      if (!members.size) rooms.delete(room);
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/send') {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { res.writeHead(413, SEC); res.end(); req.destroy(); }
      else chunks.push(c);
    });
    req.on('end', () => {
      if (size > MAX_BODY) return;
      const body = Buffer.concat(chunks).toString('utf8');
      try { const j = JSON.parse(body); if (typeof j.iv !== 'string' || typeof j.ct !== 'string') throw 0; }
      catch { res.writeHead(400, SEC); return res.end(); }
      const members = rooms.get(room);
      if (members) for (const [id, r] of members) if (id !== cid) r.write(`data: ${body}\n\n`);
      res.writeHead(204, SEC); res.end();
    });
    return;
  }

  res.writeHead(404, SEC); res.end();
}).listen(PORT, () => {
  console.log(`Silent Keep listening on :${PORT}`);
  console.log('File fingerprints (SHA-256), publish these so anyone can verify:');
  for (const [f, h] of Object.entries(hashes)) console.log(`  ${h}  ${f}`);
  console.log('Serve behind HTTPS (Caddy / nginx / a host that gives you TLS).');
});
