// Package gnosignin signs a visitor in to a website with a gno.land wallet, and remembers the browser, so that a
// hardware signer (a Ledger behind Adena, say) signs once per browser instead of once per visit.
//
// It checks two kinds of proof:
//
//   - A wallet proof. The site hands the page a phrase (Challenges). The wallet signs it with Adena's
//     SignArbitrary: an ADR-036 document of one sign/MsgSignData message, secp256k1 over SHA-256. Verify checks
//     that the signature is that key's over exactly that document, that the key is the claimed g1… address's, and
//     that the document carries the phrase.
//   - A browser-key proof. When the phrase also names a browser key (Challenges.IssueFor with a key id), the one
//     wallet signature vouches for that key: a P-256 key the page made with WebCrypto, which the browser will not
//     hand out, kept in IndexedDB. From then on VerifyBrowserKey checks that key's signature over a fresh phrase,
//     and the wallet is not asked again on that browser.
//
// gno.land's session accounts are the same idea on chain: a master key vouches once for a key that signs after it.
// But Adena refuses SignArbitrary while a session account is selected, because a key the chain can revoke proves
// less than a site would assume. So the site keeps the key, and it signs in to that site alone.
//
// The browser half is gnosignin.js (JS, ServeJS). The site keeps its own accounts, sessions and remembered keys;
// README.md says what it must do with them.
package gnosignin
