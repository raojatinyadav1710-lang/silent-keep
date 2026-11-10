'use strict';
// All crypto happens here, in the browser. The server never sees keys or plaintext.
(() => {
  const $ = (id) => document.getElementById(id);
  const enc = new TextEncoder(), dec = new TextDecoder();

  const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
  const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

  let key, roomId, myId, es, secret;

  async function sha(text) { return crypto.subtle.digest('SHA-256', enc.encode(text)); }

  // The secret (in the URL after #) is 256 random bits. Two things derive from it:
  // the room id (sent to the server, one-way) and the AES key (never sent anywhere).
  async function setup(secretB64) {
    secret = secretB64;
    const raw = unb64u(secretB64);
    if (raw.length !== 32) throw new Error('Invitation link is not valid.');
    const roomHash = await sha('silent-keep-room:' + secretB64);
    roomId = hex(roomHash);
    const keyMaterial = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
    key = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('silent-keep-v1'), info: enc.encode('aes-gcm-key') },
      keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const fpHash = new Uint8Array(await sha('silent-keep-seal:' + secretB64));
    const sigils = ['⚔', '✠', '♜', '☥', '⚜', '☣', '☸', '♔'];
    $('fp').textContent = [0, 1, 2, 3].map((i) => sigils[fpHash[i] % 8]).join(' ');
  }

  // Pad plaintext to hide message length (multiples of 256 bytes).
  async function seal(obj) {
    const body = enc.encode(JSON.stringify(obj));
    const padded = new Uint8Array(Math.ceil((body.length + 2) / 256) * 256);
    padded[0] = body.length >> 8; padded[1] = body.length & 255;
    padded.set(body, 2);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, padded);
    return { iv: b64u(iv), ct: b64u(ct) };
  }
  async function open(pkt) {
    const p = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64u(pkt.iv) }, key, unb64u(pkt.ct)));
    const len = (p[0] << 8) | p[1];
    return JSON.parse(dec.decode(p.slice(2, 2 + len)));
  }

  function add(text, cls, who) {
    const d = document.createElement('div');
    d.className = cls;
    if (who) { const w = document.createElement('span'); w.className = 'who'; w.textContent = who; d.appendChild(w); }
    d.appendChild(document.createTextNode(text)); // textContent only: never innerHTML
    const log = $('log'); log.appendChild(d); log.scrollTop = log.scrollHeight;
  }

  function connect() {
    myId = b64u(crypto.getRandomValues(new Uint8Array(12)));
    es = new EventSource(`/events?room=${roomId}&cid=${myId}`);
    es.onopen = () => { $('status').textContent = 'sealed and connected'; $('status').className = 'status on'; };
    es.onerror = () => { $('status').textContent = 'reconnecting...'; $('status').className = 'status'; };
    es.onmessage = async (e) => {
      try {
        const m = await open(JSON.parse(e.data));
        if (m.t === 'hello') add(`${m.n} has entered the chamber.`, 'sys');
        else if (m.t === 'msg') add(m.x, 'm', m.n);
      } catch { add('A message arrived that could not be verified and was discarded.', 'sys'); }
    };
  }

  async function enter(secretB64, creator) {
    await setup(secretB64);
    history.replaceState(null, '', '/#' + secretB64);
    $('gate').classList.add('hidden');
    $('chamber').classList.remove('hidden');
    add(creator ? 'Chamber forged. Copy the invitation and give it to your companion through a safe path.' :
                  'You have entered. Compare the shared seal with your companion.', 'sys');
    connect();
    setTimeout(async () => {
      const n = $('name').value.trim() || 'Knight';
      fetch(`/send?room=${roomId}&cid=${myId}`, { method: 'POST', body: JSON.stringify(await seal({ t: 'hello', n })) });
    }, 800);
  }

  $('create').onclick = () => enter(b64u(crypto.getRandomValues(new Uint8Array(32))), true)
    .catch((e) => $('gateerr').textContent = e.message);

  $('join').onclick = () => {
    const v = $('joinlink').value.trim();
    const s = v.includes('#') ? v.split('#').pop() : v;
    enter(s, false).catch((e) => $('gateerr').textContent = e.message || 'Invitation link is not valid.');
  };

  $('copy').onclick = async () => {
    try { await navigator.clipboard.writeText(location.origin + '/#' + secret); $('copy').textContent = 'Copied'; }
    catch { prompt('Copy this invitation:', location.origin + '/#' + secret); }
    setTimeout(() => $('copy').textContent = 'Copy invitation', 1500);
  };

  $('burn').onclick = () => { if (es) es.close(); location.replace('/'); };

  $('form').onsubmit = async (ev) => {
    ev.preventDefault();
    const x = $('msg').value; if (!x.trim()) return;
    const n = $('name').value.trim() || 'Knight';
    $('msg').value = '';
    add(x, 'm me', n);
    const r = await fetch(`/send?room=${roomId}&cid=${myId}`, { method: 'POST', body: JSON.stringify(await seal({ t: 'msg', n, x })) });
    if (!r.ok) add('Message could not be delivered.', 'sys');
  };

  // Integrity check: hash what this browser is actually running and compare to the server's list.
  $('verify').onclick = async () => {
    $('dlg').showModal(); const out = $('dlgout'); out.textContent = 'checking...';
    try {
      const list = await (await fetch('/integrity', { cache: 'no-store' })).json();
      const lines = [];
      for (const [file, expected] of Object.entries(list)) {
        if (file.endsWith('.jpg')) continue;
        const url = file === 'index.html' ? '/' : '/' + file;
        const got = hex(await crypto.subtle.digest('SHA-256', await (await fetch(url, { cache: 'no-store' })).arrayBuffer()));
        lines.push(`${got === expected ? 'OK ' : 'BAD'} ${file}\n    ${got}`);
      }
      out.textContent = lines.join('\n');
    } catch { out.textContent = 'Could not complete the check.'; }
  };
  $('dlgclose').onclick = () => $('dlg').close();

  // Opened via an invitation link: go straight in.
  if (location.hash.length > 20) enter(location.hash.slice(1), false).catch(() => { location.hash = ''; });
})();
