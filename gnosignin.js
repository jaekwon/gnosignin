// gnosignin.js — the browser half of github.com/jaekwon/gnosignin. It signs a visitor in with a gno.land wallet
// (Adena), and remembers the browser, so that a hardware signer signs once per browser instead of once per visit.
//
// Load it before the page's own code, set it up once, and call it:
//
//   gnosignin.configure({ request, challenge, key, slot, site })
//   const addr = await gnosignin.connect();                     // the wallet's address (Adena: connect, then the account)
//   const reply = await gnosignin.remember(addr, proof => post('/api/auth/adena', proof));
//                                                                // the wallet signs once, vouching for a new browser key
//   if (await gnosignin.keySignIn()) { ... }                     // later: this browser signs in by its key, no wallet
//
// What the site's server does with the proofs is in the README. Everything here runs in the page; the private half
// of the browser key never leaves the browser, not even to this script (WebCrypto, not extractable).
'use strict';

const gnosignin = (() => {
  const cfg = {
    challenge: '/api/auth/challenge', // GET: {id, words}; ?key=<id> names a browser key; ?for=key asks for a key's phrase
    challengeMethod: 'GET',           // or 'POST', for a site whose phrase is a POST (an Origin-checked one, say)
    key: '/api/auth/key',             // POST {id, key, sig, forget}: a session, or 401 {forgotten: true}
    slot: 'main',                     // the record this page keeps its key under (a page each, when a site has several)
    db: 'gnosignin-keys',             // the IndexedDB database the keys live in
    flag: 'gnosignin.out.',           // the localStorage name, before the slot, of "signed out on purpose"
    site: '',                         // the name Adena's connect window shows ('' is the page's host)
    headers: {},                      // added to every request this script makes itself
    request: null,                    // (method, path, body) => Promise of the parsed reply, for a site with its own;
                                      // a failure must carry .status and .data (the parsed body), as call's does
  };

  function configure(o) { Object.assign(cfg, o || {}); }

  // call is the request this script makes when the site gives none: JSON in and out, a failure as an Error with the
  // status and the parsed body.
  async function call(method, path, body) {
    if (cfg.request) return cfg.request(method, path, body);
    const init = { method, headers: Object.assign({}, cfg.headers), credentials: 'same-origin' };
    if (body !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }
    const res = await fetch(path, init);
    const text = await res.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch (e) { data = { error: text.slice(0, 200) }; }
    if (!res.ok) { const e = new Error(data.error || ('error ' + res.status)); e.status = res.status; e.data = data; throw e; }
    return data;
  }

  // --- the wallet (Adena)

  const READ_MS = 25000, HUMAN_MS = 180000; // a call the wallet answers by itself, and one a person must approve (a Ledger can take a while)
  const wcall = (p, ms = READ_MS) => Promise.race([Promise.resolve(p), new Promise((_, rej) => setTimeout(() => rej(new Error(`Adena has not answered in ${Math.round(ms / 1000)} s — if its window is open, approve it there and try again`)), ms))]);
  // 4001 doubles as ALREADY_CONNECTED and NETWORK_TIMEOUT in Adena's enum; the type field is the honest one
  const established = e => !!e && (e.code === 0 || e.type === 'CONNECTION_SUCCESS' || e.type === 'ALREADY_CONNECTED' || (e.type === undefined && e.code === 4001));

  // sortedObject and signBytesOf write a signed document the way Adena does (sortedJsonStringify, then
  // encodeCharacterSet), so the bytes the server checks are the bytes the wallet signed
  function sortedObject(v) {
    if (Array.isArray(v)) return v.map(sortedObject);
    if (v && typeof v === 'object') { const o = {}; for (const k of Object.keys(v).sort()) o[k] = sortedObject(v[k]); return o; }
    return v;
  }
  const signBytesOf = doc => JSON.stringify(sortedObject(doc)).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026');

  // connect connects the wallet and answers its address. Adena puts window.adena on the page a moment after it loads,
  // so a click right away waits up to two seconds for it.
  async function connect() {
    for (let i = 0; i < 20 && !window.adena; i++) await new Promise(r => setTimeout(r, 100));
    const a = window.adena;
    if (!a) throw new Error('Adena was not found — install the Adena wallet extension (adena.app), then reload this page');
    if (!a.SignArbitrary) throw new Error('this Adena cannot sign a phrase — update it to 1.22.2 or later');
    const est = await wcall(a.AddEstablish(cfg.site || location.hostname), HUMAN_MS);
    if (!established(est)) throw new Error((est && est.message) || 'Adena declined the connection');
    const acct = await wcall(a.GetAccount());
    if (!acct || acct.code !== 0 || !acct.data || !acct.data.address) throw new Error((acct && acct.message) || 'Adena has no account selected');
    return acct.data.address;
  }

  // refusal says why Adena did not sign, in words that say what to do. A session account selected in Adena is the
  // one most worth saying: Adena will not sign a sign-in with a session key (the chain can revoke it, so to Adena it
  // proves less than a site would assume); the main account signs once, and the browser is remembered after that.
  function refusal(r) {
    const t = r && r.type;
    if (t === 'UNSUPPORTED_TYPE') return 'Adena will not sign with this kind of account (a session account or a multisig). Select your main account in Adena and try again.';
    if (t === 'ACCOUNT_MISMATCH') return 'The account selected in Adena is not the one it named. Select your main account in Adena and try again.';
    if (t === 'SIGN_REJECTED') return 'Declined in Adena.';
    return (r && r.message) || 'the wallet did not sign';
  }

  // prove has the wallet sign the server's phrase and answers the proof to post. With a browser key (keyMake) the
  // phrase names it, and the one signature also vouches for that key.
  async function prove(addr, key) {
    const ch = await call(cfg.challengeMethod, cfg.challenge + (key ? '?key=' + key.id : ''));
    const r = await wcall(window.adena.SignArbitrary({ signer: addr, data: ch.words }), HUMAN_MS);
    if (!r || r.status !== 'success' || !r.data) throw new Error(refusal(r));
    const sg = r.data.signature || {};
    const proof = { id: ch.id, addr, pub: (sg.pubKey || {}).value, sig: sg.signature, doc: signBytesOf(r.data.signed) };
    if (key) proof.bkey = key.pub;
    return proof;
  }

  // --- the browser key: P-256, made here, kept here (IndexedDB), never extractable

  const b64of = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const hexOf = buf => Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');

  // keyDB runs one request on the key store, and gives up after 3 s: a store that never answers (some web views, an
  // old Safari's first load) must not hold a page's sign-in screen back
  function keyDB(mode, fn) {
    return Promise.race([keyDBRun(mode, fn), new Promise((_, rej) => setTimeout(() => rej(new Error('the key store did not answer')), 3000))]);
  }
  function keyDBRun(mode, fn) {
    return new Promise((resolve, reject) => {
      const open = indexedDB.open(cfg.db, 1);
      open.onupgradeneeded = () => open.result.createObjectStore('keys');
      open.onerror = () => reject(open.error);
      open.onsuccess = () => {
        const db = open.result;
        try {
          const tx = db.transaction('keys', mode);
          const req = fn(tx.objectStore('keys'));
          tx.oncomplete = () => { db.close(); resolve(req.result); };
          tx.onerror = tx.onabort = () => { db.close(); reject(tx.error); };
        } catch (e) { db.close(); reject(e); }
      };
    });
  }

  // keyGet is the key this browser keeps for the page ({id, priv, email}), or null: none, or no IndexedDB here (a
  // private window may have none)
  async function keyGet(slot) { try { const r = await keyDB('readonly', st => st.get(slot || cfg.slot)); return r && r.id && r.priv ? r : null; } catch (e) { return null; } }
  async function keyPut(rec, slot) { try { await keyDB('readwrite', st => st.put(rec, slot || cfg.slot)); return true; } catch (e) { return false; } }
  async function keyDrop(slot) { try { await keyDB('readwrite', st => st.delete(slot || cfg.slot)); } catch (e) {} }

  // keyMake makes a browser key whose private half can never leave this browser; null where WebCrypto or IndexedDB
  // is missing (an old browser, a page not over https), and the wallet then signs each time as before.
  async function keyMake() {
    try {
      if (!window.isSecureContext || !window.crypto || !crypto.subtle || !window.indexedDB) return null;
      const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
      const spki = await crypto.subtle.exportKey('spki', kp.publicKey);
      return { id: hexOf((await crypto.subtle.digest('SHA-256', spki)).slice(0, 16)), pub: b64of(spki), priv: kp.privateKey };
    } catch (e) { return null; }
  }

  // byKey has a key sign the server's key phrase and posts it: a sign-in, or with forget, the key forgotten
  async function byKey(rec, forget) {
    const ch = await call('GET', cfg.challenge + '?for=key');
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, rec.priv, new TextEncoder().encode(ch.words));
    return call('POST', cfg.key, { id: ch.id, key: rec.id, sig: b64of(sig), forget: !!forget });
  }

  // keySignIn signs this browser in with the key it keeps for the page: true when it did, false when it keeps none or
  // the server has forgotten it (then the key goes from here too). With forget, the same proof has the server forget
  // the key instead, and it goes from here. Calls made while one is under way share it: one browser, one session.
  const inflight = {};
  function keySignIn(opts) {
    const { forget = false, slot } = opts || {};
    const k = (slot || cfg.slot) + (forget ? ' forget' : '');
    if (!inflight[k]) inflight[k] = keySignInOnce(forget, slot).finally(() => { delete inflight[k]; });
    return inflight[k];
  }
  async function keySignInOnce(forget, slot) {
    const rec = await keyGet(slot);
    if (!rec) return false;
    try {
      await byKey(rec, forget);
    } catch (e) {
      if (e.status === 401 && e.data && e.data.forgotten) { await keyDrop(slot); return false; }
      throw e;
    }
    if (forget) { await keyDrop(slot); return false; }
    return true;
  }

  // remember is a wallet sign-in that also remembers this browser: a new key named in the phrase, and the key kept
  // before replaced. post sends the proof to the site's wallet sign-in and answers its reply; the new key is kept when
  // the reply says remembered (with the account's name under user.email, shown on the "Continue as" button). With
  // keep false (a shared computer) nothing is remembered, and a key kept before is forgotten.
  async function remember(addr, post, opts) {
    const { slot, keep = true } = opts || {};
    const key = keep ? await keyMake() : null;
    const old = await keyGet(slot);
    const proof = await prove(addr, key);
    if (old) proof.old = old.id;
    const r = await post(proof);
    if (old) await keyDrop(slot);
    if (key && r && r.remembered) {
      const rec = { id: key.id, priv: key.priv, email: (r.user && r.user.email) || '' };
      // a browser that cannot keep the key (a full or blocked store) has the server forget it at once, by the key's
      // own proof while it is still in hand, rather than leave a remembered browser that can never sign in
      if (!(await keyPut(rec, slot))) { try { await byKey(rec, true); } catch (e) {} }
    }
    markSignedOut(false, slot);
    return r;
  }

  // signed out on purpose: the page then offers the remembered browser as a button instead of going on by itself
  function markSignedOut(on, slot) { const k = cfg.flag + (slot || cfg.slot); try { if (on) localStorage.setItem(k, '1'); else localStorage.removeItem(k); } catch (e) {} }
  function signedOutOnPurpose(slot) { try { return localStorage.getItem(cfg.flag + (slot || cfg.slot)) === '1'; } catch (e) { return false; } }

  return { configure, connect, prove, refusal, remember, keyMake, keyGet, keyPut, keyDrop, keySignIn, markSignedOut, signedOutOnPurpose, signBytesOf };
})();
// a top-level const is no property of window: this one is, for a page that looks for window.gnosignin
if (typeof window !== 'undefined') window.gnosignin = gnosignin;
