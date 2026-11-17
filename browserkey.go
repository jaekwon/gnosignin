package gnosignin

// A remembered browser. The page makes a P-256 key the browser will not hand out (WebCrypto, extractable false,
// kept in IndexedDB); the wallet's sign-in phrase names that key (Challenges.IssueFor), so the one wallet signature
// vouches for it; from then on the key, not the wallet, signs that browser in.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"regexp"
)

// KeyRE is the shape of a browser key's id: the first 16 bytes of the SHA-256 of its public key (SPKI DER), in hex.
var KeyRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

var errKey = errors.New("that is not a browser's public key")

// KeyID is a browser key's id: a fingerprint of its public key, short enough for a phrase, long enough to stand for
// the key.
func KeyID(spki []byte) string {
	h := sha256.Sum256(spki)
	return hex.EncodeToString(h[:16])
}

// ParseBrowserKey reads a browser key's public half as the page sends it — base64 of the SPKI DER WebCrypto exports
// — and answers it with its id. Only P-256 is taken: it is what the page makes.
func ParseBrowserKey(spkiB64 string) (*ecdsa.PublicKey, string, error) {
	der, err := base64.StdEncoding.DecodeString(spkiB64)
	if err != nil || len(der) == 0 || len(der) > 200 {
		return nil, "", errKey
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, "", errKey
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, "", errors.New("the browser key is not a P-256 key")
	}
	return pub, KeyID(der), nil
}

// VerifyBrowserKey checks a remembered browser's signature over a phrase: ECDSA P-256 over the SHA-256 of the phrase's
// UTF-8 bytes, r‖s as WebCrypto gives it (64 bytes, IEEE P1363).
func VerifyBrowserKey(spkiB64, words, sigB64 string) error {
	pub, _, err := ParseBrowserKey(spkiB64)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != 64 {
		return errors.New("the signature is not 64 bytes")
	}
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	h := sha256.Sum256([]byte(words))
	if !ecdsa.Verify(pub, h[:], r, s) {
		return errors.New("the signature is not this browser key's")
	}
	return nil
}
