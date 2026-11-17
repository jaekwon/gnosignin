package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/jaekwon/gnosignin"
)

// wallet signs the way Adena's SignArbitrary does.
type wallet struct {
	priv *secp256k1.PrivateKey
	pub  string
	addr string
}

func newWallet(t *testing.T) wallet {
	p, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := p.PubKey().SerializeCompressed()
	return wallet{p, base64.StdEncoding.EncodeToString(pub), gnosignin.Address(pub)}
}

func (w wallet) proof(words string) map[string]any {
	doc, _ := json.Marshal(map[string]any{"account_number": "0", "chain_id": "test", "fee": map[string]any{"amount": []any{}, "gas": "0"}, "memo": "", "sequence": "0",
		"msgs": []any{map[string]any{"type": "sign/MsgSignData", "value": map[string]any{"data": base64.StdEncoding.EncodeToString([]byte(words)), "signer": w.addr}}}})
	h := sha256.Sum256(doc)
	sig := secpecdsa.Sign(w.priv, h[:])
	r, s := sig.R(), sig.S()
	rb, sb := r.Bytes(), s.Bytes()
	return map[string]any{"addr": w.addr, "pub": w.pub, "sig": base64.StdEncoding.EncodeToString(append(rb[:], sb[:]...)), "doc": string(doc)}
}

// bkey is a browser's key, made the way WebCrypto makes it.
type bkey struct {
	priv    *ecdsa.PrivateKey
	pub, id string
}

func newKey(t *testing.T) bkey {
	p, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&p.PublicKey)
	return bkey{p, base64.StdEncoding.EncodeToString(der), gnosignin.KeyID(der)}
}

func (k bkey) sign(words string) string {
	h := sha256.Sum256([]byte(words))
	r, s, _ := ecdsa.Sign(rand.Reader, k.priv, h[:])
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return base64.StdEncoding.EncodeToString(out)
}

// browser is one browser: its cookies, and the page's calls.
type browser struct {
	t    *testing.T
	base string
	c    *http.Client
}

func (b browser) call(method, path string, body any) (int, map[string]any) {
	var rd io.Reader
	if body != nil {
		j, _ := json.Marshal(body)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, b.base+path, rd)
	req.Header.Set(header, "gnosignin")
	res, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer res.Body.Close()
	out := map[string]any{}
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// walletIn is the page's first sign-in on a browser: a phrase naming the key, the wallet's signature, the post.
func (b browser) walletIn(w wallet, k *bkey, old string) (int, map[string]any) {
	path := "/api/auth/challenge"
	if k != nil {
		path += "?key=" + k.id
	}
	_, ch := b.call("GET", path, nil)
	p := w.proof(ch["words"].(string))
	p["id"] = ch["id"]
	if k != nil {
		p["bkey"] = k.pub
	}
	p["old"] = old
	return b.call("POST", "/api/auth/adena", p)
}

// keyIn is a remembered browser signing in by its key (forget: forgetting itself).
func (b browser) keyIn(k bkey, forget bool) (int, map[string]any) {
	_, ch := b.call("GET", "/api/auth/challenge?for=key", nil)
	return b.call("POST", "/api/auth/key", map[string]any{"id": ch["id"], "key": k.id, "sig": k.sign(ch["words"].(string)), "forget": forget})
}

func TestTheWholeFlow(t *testing.T) {
	admin, stranger := newWallet(t), newWallet(t)
	s := newSite("example.test", "", []string{admin.addr})
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	srv := httptest.NewServer(s.routes())
	defer srv.Close()
	newBrowser := func() browser { jar, _ := cookiejar.New(nil); return browser{t, srv.URL, &http.Client{Jar: jar}} }

	// the page and the script are served
	if res, err := http.Get(srv.URL + "/gnosignin.js"); err != nil || res.StatusCode != 200 {
		t.Fatalf("gnosignin.js: %v %v", res, err)
	}
	if res, _ := http.Get(srv.URL + "/"); res.StatusCode != 200 {
		t.Fatalf("the page: %d", res.StatusCode)
	}

	// a wallet that is not an admin's signs, and is turned away: no key kept, no session
	laptop := newBrowser()
	kStranger := newKey(t)
	if st, _ := laptop.walletIn(stranger, &kStranger, ""); st != 403 {
		t.Fatalf("a stranger's wallet: %d", st)
	}
	if st, _ := laptop.keyIn(kStranger, false); st != 401 {
		t.Error("a stranger's key was kept")
	}

	// the admin's wallet signs once, and the laptop is remembered
	kLaptop := newKey(t)
	st, out := laptop.walletIn(admin, &kLaptop, "")
	if st != 200 || out["remembered"] != true {
		t.Fatalf("the admin's wallet: %d %v", st, out)
	}
	if st, me := laptop.call("GET", "/api/me", nil); st != 200 || me["address"] != admin.addr {
		t.Fatalf("me: %d %v", st, me)
	}

	// a plain sign-out keeps the laptop remembered: its key signs it back in, no wallet
	laptop.call("POST", "/api/logout", map[string]any{})
	if st, _ := laptop.call("GET", "/api/me", nil); st != 401 {
		t.Fatal("still signed in after signing out")
	}
	if st, _ := laptop.keyIn(kLaptop, false); st != 200 {
		t.Fatal("the remembered laptop did not sign back in")
	}
	if st, _ := laptop.call("GET", "/api/me", nil); st != 200 {
		t.Fatal("signed in by the key, but no session")
	}

	// what may not pass: a POST without the page's header, a phrase twice, a wallet's phrase for a key, another
	// key's signature, a post carrying a key other than the one the phrase named
	req, _ := http.NewRequest("POST", srv.URL+"/api/auth/key", strings.NewReader(`{}`))
	if res, _ := http.DefaultClient.Do(req); res.StatusCode != 403 {
		t.Errorf("a POST with no header: %d", res.StatusCode)
	}
	_, ch := laptop.call("GET", "/api/auth/challenge?for=key", nil)
	body := map[string]any{"id": ch["id"], "key": kLaptop.id, "sig": kLaptop.sign(ch["words"].(string))}
	if st, _ := laptop.call("POST", "/api/auth/key", body); st != 200 {
		t.Fatal("a good key sign-in")
	}
	if st, _ := laptop.call("POST", "/api/auth/key", body); st != 400 {
		t.Errorf("a phrase used twice: %d", st)
	}
	_, ch = laptop.call("GET", "/api/auth/challenge", nil)
	if st, _ := laptop.call("POST", "/api/auth/key", map[string]any{"id": ch["id"], "key": kLaptop.id, "sig": kLaptop.sign(ch["words"].(string))}); st != 400 {
		t.Errorf("a wallet's phrase signed by a key: %d", st)
	}
	other := newKey(t)
	_, ch = laptop.call("GET", "/api/auth/challenge?for=key", nil)
	if st, out := laptop.call("POST", "/api/auth/key", map[string]any{"id": ch["id"], "key": kLaptop.id, "sig": other.sign(ch["words"].(string))}); st != 401 || out["forgotten"] != true {
		t.Errorf("another key's signature: %d %v", st, out)
	}
	_, ch = laptop.call("GET", "/api/auth/challenge?key="+other.id, nil)
	p := admin.proof(ch["words"].(string))
	p["id"], p["bkey"] = ch["id"], newKey(t).pub
	if st, _ := laptop.call("POST", "/api/auth/adena", p); st != 400 {
		t.Errorf("a key swapped after the wallet signed: %d", st)
	}
	s.tries = map[string][]time.Time{} // the limit is per minute, and this test is quicker than a reader

	// the phone signs in too; the laptop lists both and forgets the phone; then the phone comes back and signs
	// everyone else out, and the laptop cannot sign itself back in
	phone := newBrowser()
	kPhone := newKey(t)
	if st, _ := phone.walletIn(admin, &kPhone, ""); st != 200 {
		t.Fatal("the phone")
	}
	_, me := laptop.call("GET", "/api/me", nil)
	if devs := me["devices"].([]any); len(devs) != 2 { // the laptop signed in four times: still one row
		t.Fatalf("two devices: %v", devs)
	}
	live := 0
	for _, x := range s.sessions {
		if x.key == kLaptop.id {
			live++
		}
	}
	if live != 1 {
		t.Errorf("the laptop holds %d sessions; one browser, one cookie, one session", live)
	}
	if st, _ := laptop.call("POST", "/api/devices/forget", map[string]any{"id": kPhone.id}); st != 200 {
		t.Fatal("forget the phone")
	}
	if st, _ := phone.call("GET", "/api/me", nil); st != 401 {
		t.Error("the forgotten phone is still signed in")
	}
	if st, out := phone.keyIn(kPhone, false); st != 401 || out["forgotten"] != true {
		t.Error("the forgotten phone signed itself back in")
	}
	kPhone2 := newKey(t)
	phone.walletIn(admin, &kPhone2, kPhone.id)
	if st, _ := phone.call("POST", "/api/devices/others", map[string]any{}); st != 200 {
		t.Fatal("sign out everywhere else")
	}
	if st, _ := laptop.call("GET", "/api/me", nil); st != 401 {
		t.Error("the laptop is still signed in")
	}
	if st, _ := laptop.keyIn(kLaptop, false); st != 401 {
		t.Error("the laptop signed itself back in after sign out everywhere else")
	}
	if st, _ := phone.call("GET", "/api/me", nil); st != 200 {
		t.Error("the phone signed itself out")
	}
	s.tries = map[string][]time.Time{}

	// a new key replaces the one this browser held; forgetting by the key's own proof needs no session
	kPhone3 := newKey(t)
	if st, _ := phone.walletIn(admin, &kPhone3, kPhone2.id); st != 200 {
		t.Fatal("the phone again")
	}
	if st, _ := phone.keyIn(kPhone2, false); st != 401 {
		t.Error("the replaced key still signs in")
	}
	if st, out := newBrowser().keyIn(kPhone3, true); st != 200 || out["forgotten"] != true {
		t.Errorf("forget by proof: %d %v", st, out)
	}
	if st, _ := phone.keyIn(kPhone3, false); st != 401 {
		t.Error("forgotten, and still signs in")
	}

	// a key lapses a year after the wallet vouched for it, however often it was used; and an admin taken off the
	// list is out, key or not
	kOld := newKey(t)
	old := newBrowser()
	old.walletIn(admin, &kOld, "")
	for i := 0; i < 4; i++ {
		now = now.Add(100 * 24 * time.Hour)
		st, _ := old.keyIn(kOld, false)
		s.tries = map[string][]time.Time{}
		if i < 3 && st != 200 {
			t.Fatalf("day %d: a key in its year was refused: %d", (i+1)*100, st)
		}
		if i == 3 && st != 401 {
			t.Error("a key used every hundred days outlived its year")
		}
	}
	kNew := newKey(t)
	old.walletIn(admin, &kNew, "")
	delete(s.admins, admin.addr)
	if st, _ := old.keyIn(kNew, false); st != 401 {
		t.Error("a key of a wallet no longer an admin's signed in")
	}
	if st, _ := old.call("GET", "/api/me", nil); st != 401 {
		t.Error("a session of a wallet no longer an admin's still answers")
	}
}
