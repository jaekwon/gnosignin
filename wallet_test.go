package gnosignin

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// The address rule, against a pair taken off the LIVE CHAIN (manfred's account, as auth/accounts returns it).
// tm2's crypto.AddressFromPreimage uses the first 20 bytes of SHA256 and secp256k1 does not; the two give
// different addresses for one key, and a verifier on the wrong one signs every wallet in as another.
func TestAddressAgainstTheChain(t *testing.T) {
	const pubB64 = "AgBSSj+NLAA6icQ/Rf6vbrjtRbbjo197vms7Sf+eLYPI"
	const want = "g1manfred47kzduec920z88wfr64ylksmdcedlf5"
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != 33 {
		t.Fatalf("the vector itself is wrong: %v %d", err, len(pub))
	}
	if got := Address(pub); got != want {
		t.Fatalf("Address = %s, the chain says %s", got, want)
	}
	sum := sha256.Sum256(pub)
	if wrong := Bech32("g", sum[:20]); wrong == want {
		t.Fatal("sha256-truncated gave the same address — the vector cannot tell the two rules apart")
	}
	if got, err := AddressOfBase64(pubB64); err != nil || got != want {
		t.Errorf("AddressOfBase64: %s %v", got, err)
	}
	if _, err := AddressOfBase64("AAAA"); err == nil {
		t.Error("a short key was accepted")
	}
}

// Signer is a wallet the test owns.
type Signer struct {
	priv *secp256k1.PrivateKey
	Pub  string
	Addr string
}

func NewSigner(t *testing.T) Signer {
	t.Helper()
	p, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := p.PubKey().SerializeCompressed()
	return Signer{p, base64.StdEncoding.EncodeToString(pub), Address(pub)}
}

// Doc builds what Adena builds: json.Marshal of a map is its pipeline exactly — alphabetical keys, as
// sortedJsonStringify sorts them, and <, > and & escaped, as encodeCharacterSet escapes them.
func (s Signer) Doc(words, chain, signer string) string {
	b, _ := json.Marshal(map[string]any{
		"account_number": "0", "chain_id": chain, "fee": map[string]any{"amount": []any{}, "gas": "0"},
		"memo": "", "sequence": "0",
		"msgs": []any{map[string]any{"type": "sign/MsgSignData", "value": map[string]any{"data": base64.StdEncoding.EncodeToString([]byte(words)), "signer": signer}}},
	})
	return string(b)
}

func (s Signer) Sign(doc string) string {
	h := sha256.Sum256([]byte(doc))
	sig := ecdsa.Sign(s.priv, h[:])
	r, ss := sig.R(), sig.S()
	rb, sb := r.Bytes(), ss.Bytes()
	return base64.StdEncoding.EncodeToString(append(rb[:], sb[:]...))
}

const adenaVector = `{"account_number":"0","chain_id":"gnoland-1","fee":{"amount":[],"gas":"0"},"memo":"",` +
	`"msgs":[{"type":"sign/MsgSignData","value":{"data":"aGVsbG8=",` +
	`"signer":"g1jg8mtutu9khhfwc4nxmuhcpftf0pajdhfvsqf5"}}],"sequence":"0"}`

// the document the test builds is the wallet's own (Adena's sign-arbitrary.spec.ts fixture)
func TestDocMatchesAdenasPinnedPayload(t *testing.T) {
	var s Signer
	if got := s.Doc("hello", "gnoland-1", "g1jg8mtutu9khhfwc4nxmuhcpftf0pajdhfvsqf5"); got != adenaVector {
		t.Errorf("the test builds a different document from the wallet's\n ours: %s\ntheirs: %s", got, adenaVector)
	}
}

func TestVerify(t *testing.T) {
	s := NewSigner(t)
	const words, chain = "example.com: sign in with this wallet · 7f3a91", "gnoland-1"
	good := s.Doc(words, chain, s.Addr)
	if err := Verify(good, s.Sign(good), s.Pub, s.Addr, words, chain); err != nil {
		t.Fatalf("a whole, honest proof was refused: %v", err)
	}
	if err := Verify(good, s.Sign(good), s.Pub, s.Addr, words, ""); err != nil {
		t.Fatalf("the chain unchecked: %v", err)
	}
	other := NewSigner(t)
	edited := strings.Replace(good, base64.StdEncoding.EncodeToString([]byte(words)), base64.StdEncoding.EncodeToString([]byte("swapped")), 1)
	notData := strings.Replace(good, "sign/MsgSignData", "vm/m_call", 1)
	for _, c := range []struct {
		why                               string
		doc, sig, pub, addr, words, chain string
	}{
		{"another wallet's key over the same words", good, other.Sign(good), other.Pub, s.Addr, words, chain},
		{"words this browser was never given", good, s.Sign(good), s.Pub, s.Addr, "some other phrase", chain},
		{"signed for another chain", s.Doc(words, "test5", s.Addr), s.Sign(s.Doc(words, "test5", s.Addr)), s.Pub, s.Addr, words, chain},
		{"the document names a different signer", s.Doc(words, chain, other.Addr), s.Sign(s.Doc(words, chain, other.Addr)), s.Pub, s.Addr, words, chain},
		{"the claimed address is not the key's", good, s.Sign(good), s.Pub, other.Addr, words, chain},
		{"the document was edited after signing", edited, s.Sign(good), s.Pub, s.Addr, words, chain},
		{"not a sign/MsgSignData at all", notData, s.Sign(notData), s.Pub, s.Addr, words, chain},
		{"a signature of the wrong length", good, base64.StdEncoding.EncodeToString([]byte("short")), s.Pub, s.Addr, words, chain},
		{"a key of the wrong length", good, s.Sign(good), "AAAA", s.Addr, words, chain},
	} {
		if err := Verify(c.doc, c.sig, c.pub, c.addr, c.words, c.chain); err == nil {
			t.Errorf("ACCEPTED %s — it must not", c.why)
		}
	}
}

func TestChallengesOnce(t *testing.T) {
	c, now := NewChallenges(), time.Now()
	id, w, err := c.Issue("203.0.113.7", "example.com", now)
	if err != nil || id == "" || !strings.HasPrefix(w, "example.com: sign in with this wallet · ") {
		t.Fatalf("issue: %q %q %v", id, w, err)
	}
	got, fresh := c.Take(id, now)
	if got != w || !fresh {
		t.Fatalf("the phrase just issued did not come back: %q %v", got, fresh)
	}
	if _, ok := c.Take(id, now); ok {
		t.Fatal("the same phrase answered twice — a captured signature could be spent again")
	}
	id2, w2, _ := c.Issue("203.0.113.7", "example.com", now)
	if w2 == w || id2 == id {
		t.Fatal("two issues gave the same phrase or id")
	}
	if got, fresh := c.Take(id2, now.Add(Life+time.Minute)); got != w2 || fresh {
		t.Fatalf("an expired phrase must come back stale: %q fresh=%v", got, fresh)
	}
	if _, ok := c.Take("nope", now); ok {
		t.Fatal("an unknown id answered")
	}
}

func TestShort(t *testing.T) {
	if Short("g1manfred47kzduec920z88wfr64ylksmdcedlf5") != "g1manf…dlf5" || Short("g1short") != "g1short" {
		t.Error("Short")
	}
}

func TestValidAddress(t *testing.T) {
	if !ValidAddress("g1manfred47kzduec920z88wfr64ylksmdcedlf5") {
		t.Error("the live-chain address is refused")
	}
	for _, bad := range []string{"", "g1", "g1manfred47kzduec920z88wfr64ylksmdcedlf4", "g1manfred47kzduec920z88wfr64ylksmdcedlf", "G1MANFRED47KZDUEC920Z88WFR64YLKSMDCEDLF5", "cosmos1manfred47kzduec920z88wfr64ylksmdc"} {
		if ValidAddress(bad) {
			t.Errorf("%q passed", bad)
		}
	}
}
