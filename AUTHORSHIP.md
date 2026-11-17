# Authorship: what came from Jae, what came from Claude

gnosignin is Jae Kwon's: the idea of signing in to his sites with a gno.land wallet and no passwords, the idea of
signing with his hardware signer once and letting a session key do the rest, and the decision to publish this part
of his mail server as a library of its own. The code, tests and documentation were written by Claude (Anthropic's
model, run through Claude Code) under his direction. Commits carry his name and no agent trailer, by his convention.
This file keeps the record straight: his words, verbatim, and what Claude decided on its own.

## Jae's words, in order

1. **2026-10-12, for his mail server (then gnomail.io):** "no passwords, we use adena. should transfer over from
   gno.world" — Set: signing in by Adena's SignArbitrary, checked by the verifier gno.world already used. That
   verifier is `wallet.go` here.
2. **2026-10-27, for all his sites:** "as a pattern i'd like for /admin to check my authority using adena to
   authenticate with the g1ecsu... address. for all sites, remember that." — Set: every site of his signs him in
   with Adena; the copies of that code across his sites are what this library gathers.
3. **2026-11-06, on another project's signing:** "do the session account thing, obviously needed and good." — Set:
   a key that the master key vouches for once, and that signs after it.
4. **2026-11-16, for gno.email:** "shouldn't gnoemail allow me to sign in with my hardware signer just once so that
   future logins just use the session account thing?" — Set: the remembered browser (`browserkey.go`, the key half
   of `phrase.go`, and the key half of `gnosignin.js`).
5. **2026-11-17:** "review and audit things", then "and make sure the system is pushed as a reusable library but
   don't open source the whole codebase" — Set: three independent reviews of the remembered browser, whose fixes are
   in this library (the per-source cap on phrases, the key's fixed year, one sign-in at a time, a browser that cannot
   keep its key having the server forget it), and this repository. The mail server it came from stays private.

## What Claude decided on its own

- Keeping the session key in the browser, rather than using gno.land's session accounts: Adena refuses
  SignArbitrary while a session account is selected (a key the chain can revoke "proves less than the dApp will
  assume", in Adena's own source), so no site can sign anyone in by one.
- The key itself: P-256 made by WebCrypto, not extractable, kept in IndexedDB; its id is the first 16 bytes of the
  SHA-256 of its public key; the wallet's phrase names that id, so the one wallet signature vouches for that key and
  no other.
- A year from the wallet's signature before a key lapses, used or not; a key per page; the wording of the phrases;
  and the advice that a key's session be trusted like a gno.land session account, not like its master (README).
- The name, the layout of the repository, and the licence: the one Jae chose for gnosh (the GNO Network GPL with his
  strong attribution terms; see LICENSE.md), applied here because he named none for this library.
