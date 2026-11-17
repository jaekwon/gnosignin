package gnosignin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func p256(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, string, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k, base64.StdEncoding.EncodeToString(der), KeyID(der)
}

// p1363 signs the way crypto.subtle.sign does for ECDSA: SHA-256 of the bytes, r‖s at the curve's width.
func p1363(t *testing.T, k *ecdsa.PrivateKey, words string) string {
	t.Helper()
	h := sha256.Sum256([]byte(words))
	r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
	if err != nil {
		t.Fatal(err)
	}
	w := (k.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*w)
	r.FillBytes(out[:w])
	s.FillBytes(out[w:])
	return base64.StdEncoding.EncodeToString(out)
}

func TestBrowserKeyVerify(t *testing.T) {
	k, pub, id := p256(t, elliptic.P256())
	if !KeyRE.MatchString(id) {
		t.Fatalf("id %q", id)
	}
	if _, got, err := ParseBrowserKey(pub); err != nil || got != id {
		t.Fatalf("parse: %q %v", got, err)
	}
	words := "example.com: this browser signs in with the key it keeps · abc"
	sig := p1363(t, k, words)
	if err := VerifyBrowserKey(pub, words, sig); err != nil {
		t.Fatalf("a good signature refused: %v", err)
	}
	if VerifyBrowserKey(pub, words+" ", sig) == nil {
		t.Error("a signature over other words passed")
	}
	_, pub2, _ := p256(t, elliptic.P256())
	if VerifyBrowserKey(pub2, words, sig) == nil {
		t.Error("another key's signature passed")
	}
	raw, _ := base64.StdEncoding.DecodeString(sig)
	for _, bad := range []string{"", "!!", base64.StdEncoding.EncodeToString(raw[:63]), base64.StdEncoding.EncodeToString(make([]byte, 64))} {
		if VerifyBrowserKey(pub, words, bad) == nil {
			t.Errorf("signature %q passed", bad)
		}
	}
	// what the page never makes is never taken: another curve, junk
	k384, pub384, _ := p256(t, elliptic.P384())
	if VerifyBrowserKey(pub384, words, p1363(t, k384, words)) == nil {
		t.Error("a P-384 key passed")
	}
	for _, bad := range []string{"", "AAAA", base64.StdEncoding.EncodeToString(make([]byte, 300)), "not base64"} {
		if _, _, err := ParseBrowserKey(bad); err == nil {
			t.Errorf("public key %q taken", bad)
		}
	}
}

func TestPhrasesForKeys(t *testing.T) {
	c := NewChallenges()
	now := time.Now()
	key := strings.Repeat("ab", 16)
	id, words, err := c.IssueFor("203.0.113.7", "example.com", "", key, now)
	if err != nil || !strings.Contains(words, "remember this browser (key "+key+")") || !strings.HasPrefix(words, "example.com: sign in with this wallet") {
		t.Fatalf("a wallet's phrase naming a key: %q %v", words, err)
	}
	if p, fresh := c.TakePhrase(id, now); !fresh || p.Words != words || p.Kind != "" || p.Key != key {
		t.Errorf("taken back: %+v %v", p, fresh)
	}
	if p, _ := c.TakePhrase(id, now); p.Words != "" {
		t.Error("a phrase answered twice")
	}
	id, words, _ = c.IssueFor("203.0.113.7", "example.com", KindKey, key, now)
	if p, _ := c.TakePhrase(id, now); p.Kind != KindKey || p.Key != "" || strings.Contains(words, "wallet") {
		t.Errorf("a key's phrase: %+v %q", p, words)
	}
	if _, _, err := c.IssueFor("203.0.113.7", "example.com", "", "not-a-key", now); err == nil {
		t.Error("a malformed key named")
	}
	if _, _, err := c.IssueFor("203.0.113.7", "example.com", "other", "", now); err == nil {
		t.Error("an unknown purpose")
	}
	// the old way, unchanged: a wallet's plain phrase, Take answering its words
	id, words, _ = c.Issue("203.0.113.7", "example.com", now)
	if got, fresh := c.Take(id, now.Add(Life+time.Second)); got != words || fresh || !strings.HasPrefix(words, "example.com: sign in with this wallet · ") {
		t.Errorf("plain: %q %q %v", got, words, fresh)
	}
	// a key's phrase is signed by code at once: it lasts KeyLife, not a wallet's Life
	id, _, _ = c.IssueFor("203.0.113.7", "example.com", KindKey, "", now)
	if _, fresh := c.TakePhrase(id, now.Add(KeyLife+time.Second)); fresh {
		t.Error("a key's phrase outlived KeyLife")
	}
}

// One source holds at most MaxPerSource phrases: its own oldest go, and a flood from it leaves everyone else's alone.
func TestPhrasesPerSource(t *testing.T) {
	c, now := NewChallenges(), time.Now()
	mine, _, _ := c.Issue("198.51.100.1", "example.com", now)
	first, _, _ := c.Issue("203.0.113.9", "example.com", now)
	for i := 0; i < MaxPerSource*10; i++ {
		if _, _, err := c.Issue("203.0.113.9", "example.com", now.Add(time.Duration(i+1)*time.Millisecond)); err != nil {
			t.Fatalf("the flood was refused rather than trimmed: %v", err)
		}
	}
	if len(c.at) != MaxPerSource+1 || c.counts["203.0.113.9"] != MaxPerSource {
		t.Fatalf("held %d phrases, %d of them the flood's", len(c.at), c.counts["203.0.113.9"])
	}
	if p, _ := c.TakePhrase(first, now); p.Words != "" {
		t.Error("the flood's oldest phrase survived its own flood")
	}
	if p, fresh := c.TakePhrase(mine, now); p.Words == "" || !fresh {
		t.Error("another reader's phrase was crowded out")
	}
	if _, ok := c.counts["198.51.100.1"]; ok {
		t.Error("a source with nothing outstanding is still counted")
	}
}

func TestSourceOf(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":          "203.0.113.7",
		"::ffff:203.0.113.7":   "203.0.113.7",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1": "2001:db8:1:2::/64",
		"not an address":       "not an address",
	} {
		if got := SourceOf(in); got != want {
			t.Errorf("SourceOf(%q) = %q, want %q", in, got, want)
		}
	}
}
