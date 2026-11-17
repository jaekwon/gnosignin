# gnosignin

Sign in to a website with a [gno.land](https://gno.land) wallet, and remember the browser: a hardware signer (a
Ledger behind [Adena](https://adena.app)) signs once per browser, not once per visit. No passwords.

It is the sign-in of [gno.email](https://gno.email), taken out so that other sites can share it: Go for the server,
one script for the page.

## How it works

1. **The first time on a browser**, the page makes a key that the browser keeps and will not hand out (WebCrypto
   P-256, not extractable, in IndexedDB). It asks the server for a phrase naming that key, and the wallet signs the
   phrase: "example.com: sign in with this wallet and remember this browser (key 3f9a…) · nonce". That one
   signature signs the visitor in and vouches for the key. The server keeps the key, with the signature as its
   proof.
2. **After that**, the browser key signs a fresh phrase whenever the visitor signs in again: when the session ends,
   or from a "Continue as …" button after a sign-out. No wallet window, no Ledger.
3. **A remembered browser is forgotten** from its own sign-in screen, from any signed-in device, or a year after the
   wallet vouched for it, however often it was used.

Why not gno.land's [session accounts](https://github.com/gnolang/gno/blob/master/tm2/adr/adr-002-session-subaccounts.md),
which are the same idea on chain? Adena refuses to sign a phrase while a session account is selected, because a key
the chain can revoke proves less than a site would assume. So no site can sign anyone in with one. gnosignin keeps
the key on the site, where it signs in to that site alone. When Adena refuses for this reason, `gnosignin.refusal`
tells the visitor to select their main account.

## A key proves the browser, not the person at it

Treat a session made by a browser key like a gno.land session account: good for everyday use, not for what only the
master key should do. gno.email lets a key's session read and send the account's own mail. For anything that reaches
further, it answers 403 `{"wallet": true}` and the page has the wallet sign once, then tries again. That covers other
people's mail, the admin pages, passwords and two-factor, forwarding mail to a new address, and deleting the account.
Its admin pages remember no browser at all. Decide where your own site draws that line before you let keys in.

## The server (Go)

```go
import "github.com/jaekwon/gnosignin"

var phrases = gnosignin.NewChallenges()

mux.HandleFunc("GET /gnosignin.js", gnosignin.ServeJS)
```

The site keeps its own accounts, sessions and remembered keys. Its three endpoints must do the following, in this
order. [example/](example/) is a complete, tested site that does all of it: an admin page that only listed wallets
may enter.

**`GET /api/auth/challenge`** hands out a phrase:
`phrases.IssueFor(gnosignin.SourceOf(readerIP), site, kind, key, now)`. `?key=<id>` (an id matching
`gnosignin.KeyRE`) names the browser key a wallet's sign-in is to vouch for. `?for=key` asks for the phrase a
remembered browser's key signs (kind `gnosignin.KindKey`). The source caps how many phrases one reader holds at once
(`MaxPerSource`, an IPv6 /64 counted as one), so a flood from a few addresses cannot crowd everyone else out.
Rate-limit the endpoint too.

**`POST /api/auth/adena`** `{id, addr, pub, sig, doc, bkey, old}`, the wallet's sign-in:

- `p, fresh := phrases.TakePhrase(id, now)`: refuse an unknown, used or stale phrase, and one whose `p.Kind` is not
  `""`.
- `gnosignin.Verify(doc, sig, pub, addr, p.Words, chain)`.
- When `p.Key != ""`: `_, kid, err := gnosignin.ParseBrowserKey(bkey)` must give `kid == p.Key`, or refuse. Then
  store the key for the account, with an expiry a year out and the proof `{addr, pub, sig, doc}`.
- When `old` is a key of this same account, forget it: this browser has replaced it.
- Start the session, linked to the key, and answer `{remembered: true, user: {email}}` when a key was stored. The page
  shows `user.email` on its "Continue as" button; any name will do.

**`POST /api/auth/key`** `{id, key, sig, forget}`, a remembered browser:

- `p, fresh := phrases.TakePhrase(id, now)`, and `p.Kind` must be `gnosignin.KindKey` (fresh for `KeyLife`).
- Look the key up. If it is not stored, or past its year, answer 401 with `{"forgotten": true}`; the page then drops
  its copy. If the lookup itself fails (a database that cannot answer), answer 5xx without `forgotten`, so the page
  keeps its key.
- `gnosignin.VerifyBrowserKey(pub, p.Words, sig)`; if it fails, answer the same 401.
- With `forget`, forget the key and answer `{forgotten: true}`. Otherwise start a session marked as made by a key, in
  one transaction that also checks the key is still there. A browser has one cookie, so end the key's older sessions.

**And everywhere a site signs people out:**

- ending a device's session from another device forgets that device's key;
- "sign out everywhere else" forgets every key but this browser's;
- a new password forgets every key but this browser's;
- deleting the account forgets them all.

A remembered browser stays listed with the other devices, once, even when it has no session, so it is never out of
sight. Every POST needs a header a cross-site form cannot send (a custom header, or a same-origin check). The session
cookie should be `HttpOnly`, `Secure` and `SameSite=Lax`.

## The page

```html
<script src="/gnosignin.js"></script>
<script>
gnosignin.configure({ headers: { 'X-Requested-With': 'gnosignin' } }); // or { request } to use the page's own fetch

// the first time: the wallet signs once, and this browser is remembered (keep: false on a shared computer)
async function signInWithWallet(keep) {
  const addr = await gnosignin.connect();
  return gnosignin.remember(addr, proof => post('/api/auth/adena', proof), { keep });
}

// after that, no wallet: true when this browser signed in by its key
async function signInQuietly() {
  return !gnosignin.signedOutOnPurpose() && gnosignin.keySignIn();
}

// signing out: remembered (one button next time), or forgotten
async function signOut(forget) {
  gnosignin.markSignedOut(true);
  if (forget) await gnosignin.keySignIn({ forget: true });
}
</script>
```

`configure` takes:

- `challenge` and `key`: the two endpoint paths;
- `slot`: a name per page, when one origin has several;
- `site`: the name Adena's connect window shows;
- `db` and `flag`: where the key and the signed-out mark are kept;
- `headers`;
- `request`: for a page that has its own way of calling its server.

Concurrent `keySignIn` calls share one sign-in. A browser that cannot store the key has the server forget it at once.
The key store gives up after 3 seconds rather than hold a page's sign-in screen back.

## Tests

`go test ./...` covers:

- the wallet proof, against a live-chain address and Adena's own fixture;
- the phrases and their per-source cap;
- the browser keys;
- the example server's whole flow.

gno.email runs the page half in a real browser on every deploy.

## Licence

The [GNO Network General Public License](https://gno.land/license), version 6, with Jae Kwon's strong attribution
terms: a site that uses gnosignin shows "sign-in by gnosignin", linked to this repository, where its other credits
are. See [LICENSE.md](LICENSE.md). Who wrote what is in [AUTHORSHIP.md](AUTHORSHIP.md).
