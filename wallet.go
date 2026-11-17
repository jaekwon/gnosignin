package gnosignin

// The wallet proof: Adena's SignArbitrary (ADR-036), checked as gno.world, gno.email and gno.shop have checked it
// since 2026-10, against a live-chain vector and Adena's own fixture (wallet_test.go).
//
// Verify checks the EXACT bytes the page says were signed and never re-serializes them. Adena builds its document
// with sortedJsonStringify and encodeCharacterSet, and reproducing that byte for byte is the one part of this that
// would fail closed and silently. Verifying the given bytes, then reading the fields out of them, is equally safe
// and has nothing to get wrong.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // tm2 derives secp256k1 addresses with it; the hash is their choice
)

// AddrRE is the shape of a gno address.
var AddrRE = regexp.MustCompile(`^g1[02-9ac-hj-np-z]{38}$`)

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(v []int) int {
	gen := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, x := range v {
		b := chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ x
		for i := 0; i < 5; i++ {
			if (b>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32Expand(hrp string) []int {
	out := make([]int, 0, len(hrp)*2+1)
	for _, c := range hrp {
		out = append(out, int(c)>>5)
	}
	out = append(out, 0)
	for _, c := range hrp {
		out = append(out, int(c)&31)
	}
	return out
}

// Bech32 is the BIP-173 encoding, a checksum rather than a cipher: written here instead of pulled in, and held to
// the live-chain vector in the tests.
func Bech32(hrp string, data []byte) string {
	var five []int
	acc, bits := 0, 0
	for _, b := range data {
		acc = acc<<8 | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			five = append(five, (acc>>bits)&31)
		}
	}
	if bits > 0 {
		five = append(five, (acc<<(5-bits))&31)
	}
	chk := append(append(bech32Expand(hrp), five...), 0, 0, 0, 0, 0, 0)
	pm := bech32Polymod(chk) ^ 1
	out := make([]byte, 0, len(hrp)+1+len(five)+6)
	out = append(out, hrp...)
	out = append(out, '1')
	for _, x := range five {
		out = append(out, bech32Charset[x])
	}
	for i := 0; i < 6; i++ {
		out = append(out, bech32Charset[(pm>>(5*(5-i)))&31])
	}
	return string(out)
}

// Address is the g1… address of a compressed secp256k1 key: RIPEMD160(SHA256(the raw 33 bytes)), bech32 under "g".
// NOT tmhash.SumTruncated: tm2's crypto.AddressFromPreimage takes the first 20 bytes of SHA256, and that is a
// DIFFERENT address for the same key. Taking the wrong one would sign every wallet in as somebody else, quietly.
func Address(pub []byte) string {
	sum := sha256.Sum256(pub)
	r := ripemd160.New()
	r.Write(sum[:])
	return Bech32("g", r.Sum(nil))
}

// AddressOfBase64 is the address of a key as Adena hands it out (base64 of the 33 compressed bytes).
func AddressOfBase64(pubB64 string) (string, error) {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != 33 {
		return "", errors.New("the public key is not 33 compressed bytes")
	}
	if _, err := secp256k1.ParsePubKey(pub); err != nil {
		return "", errors.New("the public key does not parse")
	}
	return Address(pub), nil
}

// signedDoc is the part of an ADR-036 document Verify insists on reading.
type signedDoc struct {
	ChainID string `json:"chain_id"`
	Msgs    []struct {
		Type  string `json:"type"`
		Value struct {
			Data   string `json:"data"`
			Signer string `json:"signer"`
		} `json:"value"`
	} `json:"msgs"`
}

// ErrShape is every way a wallet proof can fail; the wrapped text says which.
var ErrShape = errors.New("that signature does not prove this wallet")

// Verify checks a SignArbitrary proof. doc is the exact string the wallet signed; sigB64 and pubB64 are as Adena
// returns them. It answers nil only when the signature is that key's over that string, the key is that address's,
// and the document carries the words asked for (and the chain, when one is required).
func Verify(doc, sigB64, pubB64, wantAddr, wantWords, wantChain string) error {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != 33 {
		return fmt.Errorf("%w: the public key is not 33 compressed bytes", ErrShape)
	}
	if got := Address(pub); got != wantAddr {
		return fmt.Errorf("%w: that key belongs to %s", ErrShape, Short(got))
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != 64 {
		return fmt.Errorf("%w: the signature is not 64 bytes", ErrShape)
	}
	key, err := secp256k1.ParsePubKey(pub)
	if err != nil {
		return fmt.Errorf("%w: the public key does not parse", ErrShape)
	}
	var r, s secp256k1.ModNScalar
	if r.SetByteSlice(sig[:32]) || s.SetByteSlice(sig[32:]) { // true means it overflowed the curve order
		return fmt.Errorf("%w: the signature is out of range", ErrShape)
	}
	h := sha256.Sum256([]byte(doc))
	if !ecdsa.NewSignature(&r, &s).Verify(h[:], key) {
		return fmt.Errorf("%w: the signature is not that key's", ErrShape)
	}
	var d signedDoc // only now, on bytes the wallet is known to have signed, is it worth reading what they say
	if json.Unmarshal([]byte(doc), &d) != nil || len(d.Msgs) != 1 {
		return fmt.Errorf("%w: the signed document is not one message", ErrShape)
	}
	m := d.Msgs[0]
	switch {
	case m.Type != "sign/MsgSignData":
		return fmt.Errorf("%w: it signs %q, not a plain message", ErrShape, m.Type)
	case m.Value.Signer != wantAddr:
		return fmt.Errorf("%w: it names another signer", ErrShape)
	// base64, not the words themselves: Adena's makeArbitraryMessageDoc does toBase64(toUtf8(data))
	case m.Value.Data != base64.StdEncoding.EncodeToString([]byte(wantWords)):
		return fmt.Errorf("%w: it signs something other than this browser's phrase", ErrShape)
	case wantChain != "" && d.ChainID != wantChain:
		return fmt.Errorf("%w: it was signed for %q", ErrShape, d.ChainID)
	}
	return nil
}

// Short is an address as a line shows it.
func Short(addr string) string {
	if len(addr) > 12 {
		return addr[:6] + "…" + addr[len(addr)-4:]
	}
	return addr
}
