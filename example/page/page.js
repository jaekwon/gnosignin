// page.js: the example's admin page. A wallet signs once per browser; the browser's own key signs after that.
'use strict';
gnosignin.configure({ headers: { 'X-Requested-With': 'gnosignin' } });

const app = document.getElementById('app');
function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) { if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v); }
  for (const k of kids) if (k != null) e.append(k);
  return e;
}
async function call(method, path, body) {
  const init = { method, headers: { 'X-Requested-With': 'gnosignin' }, credentials: 'same-origin' };
  if (body !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }
  const res = await fetch(path, init);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) { const e = new Error(data.error || ('error ' + res.status)); e.status = res.status; e.data = data; throw e; }
  return data;
}

// show draws the page for whoever is signed in; with nobody, a remembered browser goes back in by its key first,
// unless its reader signed out on purpose
async function show(note) {
  let me = null;
  try { me = await call('GET', '/api/me'); } catch (e) { if (e.status !== 401) { app.replaceChildren(el('p', { class: 'err' }, e.message)); return; } }
  if (me) return signedIn(me);
  if (!note && !gnosignin.signedOutOnPurpose()) { try { if (await gnosignin.keySignIn()) return show(); } catch (e) {} }
  signIn(note);
}

async function signIn(note) {
  const err = el('p', { class: 'err' }, note || '');
  const adena = el('button', { onclick: async () => {
    err.textContent = '';
    try {
      const addr = await gnosignin.connect();
      await gnosignin.remember(addr, proof => call('POST', '/api/auth/adena', proof));
      show();
    } catch (e) { err.textContent = e.message || String(e); }
  } }, 'Sign in with Adena');
  const rows = [];
  const rec = await gnosignin.keyGet();
  if (rec) {
    rows.push(el('p', {}, el('button', { onclick: async () => {
      try { if (await gnosignin.keySignIn()) { gnosignin.markSignedOut(false); return show(); } err.textContent = 'This browser is not remembered any more — sign in with your wallet.'; signIn(err.textContent); }
      catch (e) { err.textContent = e.message || String(e); }
    } }, 'Continue as ' + (rec.email || 'this browser'))),
    el('p', { class: 'muted' }, 'This browser is remembered: no wallet needed. ', el('a', { href: '#', onclick: async e => {
      e.preventDefault();
      try { await gnosignin.keySignIn({ forget: true }); } catch (ex) { await gnosignin.keyDrop(); }
      signIn('Forgotten.');
    } }, 'Forget this browser')));
  }
  app.replaceChildren(...rows, el('p', {}, adena), err);
}

function signedIn(me) {
  const list = el('ul', {}, ...me.devices.map(d => el('li', {},
    (d.ua || 'a browser').slice(0, 60), d.current ? ' · this browser' : '', d.remembered ? (d.away ? ' · remembered, signed out' : ' · remembered') : '', ' ',
    d.current ? null : el('button', { onclick: async () => { await call('POST', '/api/devices/forget', { id: d.id }); show(); } }, d.remembered ? 'Forget' : 'Sign out'))));
  app.replaceChildren(
    el('p', {}, 'Signed in as ', el('code', {}, me.address), '.'),
    el('h2', {}, 'Your devices'), list,
    el('p', {}, el('button', { onclick: async () => { await call('POST', '/api/devices/others', {}); show(); } }, 'Sign out everywhere else')),
    el('p', {},
      el('button', { onclick: async () => { gnosignin.markSignedOut(true); await call('POST', '/api/logout', {}); show('Signed out.'); } }, 'Sign out'), ' ',
      el('button', { onclick: async () => { await call('POST', '/api/logout', { forget: true }); await gnosignin.keyDrop(); show('Signed out, and this browser forgotten.'); } }, 'Sign out and forget this browser')));
}

show();
