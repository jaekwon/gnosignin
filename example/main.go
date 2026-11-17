// Command example is a site whose admin page only listed wallets may enter, signed in with gnosignin: the wallet (a
// Ledger behind Adena, say) signs once per browser, and the browser's own key signs after that. It keeps everything
// in memory; a real site keeps the remembered keys where they survive a restart.
//
//	go run ./example -admins g1…,g1… -listen 127.0.0.1:8080
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jaekwon/gnosignin"
)

//go:embed page
var pageFS embed.FS

const (
	keyLife     = 365 * 24 * time.Hour // a remembered browser lapses a year after the wallet vouched for it, used or not
	sessionLife = 30 * 24 * time.Hour
	cookieName  = "session"
	header      = "X-Requested-With" // every POST must carry it: a form on another site cannot set it
	triesPerMin = 20                 // sign-ins and phrases a minute from one address
)

type site struct {
	name    string          // the site's name in every phrase
	admins  map[string]bool // the wallets that may enter
	chain   string          // the chain a wallet's proof must name ("" for any)
	phrases *gnosignin.Challenges
	now     func() time.Time

	mu       sync.Mutex
	keys     map[string]*key        // remembered browsers, by the key's id
	sessions map[string]*session    // by the SHA-256 of the cookie's token: a leaked table holds no live cookie
	tries    map[string][]time.Time // recent sign-in attempts, by the reader's address
}

type key struct {
	id, addr, pub, proof, ua string
	created, used, expires   time.Time
}

type session struct {
	addr, key, ua    string
	created, expires time.Time
}

func newSite(name, chain string, admins []string) *site {
	s := &site{name: name, chain: chain, admins: map[string]bool{}, phrases: gnosignin.NewChallenges(), now: time.Now,
		keys: map[string]*key{}, sessions: map[string]*session{}, tries: map[string][]time.Time{}}
	for _, a := range admins {
		if a = strings.TrimSpace(a); a != "" {
			s.admins[a] = true
		}
	}
	return s
}

func (s *site) routes() http.Handler {
	m := http.NewServeMux()
	static, _ := fs.Sub(pageFS, "page")
	m.Handle("GET /", http.FileServerFS(static))
	m.HandleFunc("GET /gnosignin.js", gnosignin.ServeJS)
	m.HandleFunc("GET /api/auth/challenge", s.challenge)
	m.HandleFunc("POST /api/auth/adena", s.post(s.walletSignIn))
	m.HandleFunc("POST /api/auth/key", s.post(s.keySignIn))
	m.HandleFunc("POST /api/logout", s.post(s.logout))
	m.HandleFunc("GET /api/me", s.me)
	m.HandleFunc("POST /api/devices/others", s.post(s.signOutOthers))
	m.HandleFunc("POST /api/devices/forget", s.post(s.forgetDevice))
	return m
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "where to listen")
	admins := flag.String("admins", "", "the g1 addresses that may enter, comma-separated")
	name := flag.String("site", "", "the site's name in the phrases (default: the listen address)")
	chain := flag.String("chain", "", "the chain id a wallet's proof must name, e.g. gnoland-1 (default: any)")
	flag.Parse()
	list := strings.Split(*admins, ",")
	for _, a := range list {
		if a = strings.TrimSpace(a); a != "" && !gnosignin.AddrRE.MatchString(a) {
			log.Fatalf("-admins: %q is not a g1 address", a)
		}
	}
	if *name == "" {
		*name = *listen
	}
	log.Printf("listening on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, newSite(*name, *chain, list).routes()))
}

// --- the endpoints

// challenge hands out a phrase: a wallet's, naming the browser key it is to vouch for with ?key=<id>; or, with
// ?for=key, the one a remembered browser's key signs.
func (s *site) challenge(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r) {
		fail(w, 429, "too many tries; wait a minute")
		return
	}
	kind, key := "", r.URL.Query().Get("key")
	if r.URL.Query().Get("for") == gnosignin.KindKey {
		kind, key = gnosignin.KindKey, ""
	}
	id, words, err := s.phrases.IssueFor(source(r), s.name, kind, key, s.now())
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	reply(w, map[string]any{"id": id, "words": words})
}

// walletSignIn checks the wallet's proof, remembers the browser key its phrase named, and starts a session.
func (s *site) walletSignIn(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID, Addr, Pub, Sig, Doc, BKey, Old string }
	if !readJSON(w, r, &in) {
		return
	}
	p, fresh := s.phrases.TakePhrase(in.ID, s.now())
	if p.Words == "" || !fresh || p.Kind != "" {
		fail(w, 400, "ask for a phrase first")
		return
	}
	if err := gnosignin.Verify(in.Doc, in.Sig, in.Pub, in.Addr, p.Words, s.chain); err != nil {
		fail(w, 401, err.Error())
		return
	}
	if !s.admins[in.Addr] {
		fail(w, 403, "this wallet may not enter")
		return
	}
	if p.Key != "" { // the phrase named a key: the post must carry that very key
		if _, id, err := gnosignin.ParseBrowserKey(in.BKey); err != nil || id != p.Key {
			fail(w, 400, "the browser key is not the one the phrase names")
			return
		}
	}
	proof, _ := json.Marshal(map[string]string{"addr": in.Addr, "pub": in.Pub, "sig": in.Sig, "doc": in.Doc})
	now := s.now()
	s.mu.Lock()
	if old := s.keys[in.Old]; old != nil && old.addr == in.Addr && in.Old != p.Key { // replaced by this browser's new key
		s.forgetLocked(old.id)
	}
	remembered := false
	if p.Key != "" && s.keys[p.Key] == nil {
		ua := r.UserAgent()
		if len(ua) > 200 {
			ua = ua[:200]
		}
		s.keys[p.Key] = &key{id: p.Key, addr: in.Addr, pub: in.BKey, proof: string(proof), ua: ua, created: now, used: now, expires: now.Add(keyLife)}
		remembered = true
	}
	bkey := ""
	if remembered {
		bkey = p.Key
	}
	tok := s.startLocked(in.Addr, bkey, r.UserAgent())
	s.mu.Unlock()
	setCookie(w, r, tok)
	reply(w, map[string]any{"ok": true, "remembered": remembered, "user": map[string]string{"email": gnosignin.Short(in.Addr), "address": in.Addr}})
}

// keySignIn signs a remembered browser in by its key, or with forget, forgets it. A key that is gone, lapsed, no
// longer an admin's, or does not match its signature is answered "forgotten", and the page drops its copy.
func (s *site) keySignIn(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID, Key, Sig string
		Forget       bool
	}
	if !readJSON(w, r, &in) {
		return
	}
	p, fresh := s.phrases.TakePhrase(in.ID, s.now())
	if p.Words == "" || !fresh || p.Kind != gnosignin.KindKey {
		fail(w, 400, "ask for a phrase first")
		return
	}
	now := s.now()
	s.mu.Lock()
	k := s.keys[in.Key]
	if k == nil || !now.Before(k.expires) || !s.admins[k.addr] || gnosignin.VerifyBrowserKey(k.pub, p.Words, in.Sig) != nil {
		s.mu.Unlock()
		writeJSON(w, 401, map[string]any{"error": "this browser is not remembered here any more — sign in with your wallet", "forgotten": true})
		return
	}
	if in.Forget {
		s.forgetLocked(k.id)
		s.mu.Unlock()
		reply(w, map[string]any{"ok": true, "forgotten": true})
		return
	}
	k.used = now // the year runs from the wallet's signature, not from the last use: a stolen key does not keep itself alive
	tok := s.startLocked(k.addr, k.id, r.UserAgent())
	s.mu.Unlock()
	setCookie(w, r, tok)
	reply(w, map[string]any{"ok": true, "user": map[string]string{"email": gnosignin.Short(k.addr), "address": k.addr}})
}

// logout ends this browser's session; the browser stays remembered unless the page says forget.
func (s *site) logout(w http.ResponseWriter, r *http.Request) {
	var in struct{ Forget bool }
	json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&in) // no body is a plain sign-out
	s.mu.Lock()
	if h, se := s.sessionLocked(r); se != nil {
		if in.Forget && se.key != "" {
			s.forgetLocked(se.key)
		}
		delete(s.sessions, h)
	}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteLaxMode})
	reply(w, map[string]any{"ok": true})
}

// device is one browser the account is signed in on, or remembered by, as the admin page lists them.
type device struct {
	ID         string    `json:"id"` // the key's id for a remembered browser, else the session's handle
	UA         string    `json:"ua"`
	Since      time.Time `json:"since"`
	Current    bool      `json:"current"`
	Remembered bool      `json:"remembered"`
	Away       bool      `json:"away"` // remembered, with no session now
}

// me is who is signed in, with every device of theirs: their sessions, and the remembered browsers with none.
func (s *site) me(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, se := s.sessionLocked(r)
	if se == nil || !s.admins[se.addr] {
		fail(w, 401, "sign in")
		return
	}
	now := s.now()
	var list []device
	byKey := map[string]*device{} // one row per remembered browser, however many sessions it has had
	for h, x := range s.sessions {
		if x.addr != se.addr || !now.Before(x.expires) {
			continue
		}
		if k := s.keys[x.key]; x.key != "" && k != nil {
			d := byKey[x.key]
			if d == nil {
				d = &device{ID: k.id, UA: k.ua, Since: x.created, Remembered: true}
				byKey[x.key] = d
			}
			d.Current = d.Current || h == cur
			if x.created.After(d.Since) {
				d.Since = x.created
			}
			continue
		}
		list = append(list, device{ID: "s" + h[:11], UA: x.ua, Since: x.created, Current: h == cur})
	}
	for _, k := range s.keys {
		if k.addr != se.addr || !now.Before(k.expires) {
			continue
		}
		if d := byKey[k.id]; d != nil {
			list = append(list, *d)
		} else {
			list = append(list, device{ID: k.id, UA: k.ua, Since: k.used, Remembered: true, Away: true})
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Since.After(list[j].Since) })
	reply(w, map[string]any{"address": se.addr, "devices": list})
}

// signOutOthers is "sign out everywhere else": every other session ends, and every other remembered browser is
// forgotten, so none of them signs itself back in.
func (s *site) signOutOthers(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, se := s.sessionLocked(r)
	if se == nil {
		fail(w, 401, "sign in")
		return
	}
	n := 0
	for h, x := range s.sessions {
		if x.addr == se.addr && h != cur {
			delete(s.sessions, h)
			n++
		}
	}
	for id, k := range s.keys {
		if k.addr == se.addr && id != se.key {
			delete(s.keys, id)
		}
	}
	reply(w, map[string]any{"ok": true, "sessions": n})
}

// forgetDevice ends one of the account's devices from another: its session, and its key with every session behind it.
func (s *site) forgetDevice(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID string }
	if !readJSON(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, se := s.sessionLocked(r)
	if se == nil {
		fail(w, 401, "sign in")
		return
	}
	if k := s.keys[in.ID]; k != nil && k.addr == se.addr {
		s.forgetLocked(k.id)
		reply(w, map[string]any{"ok": true})
		return
	}
	for h, x := range s.sessions {
		if x.addr == se.addr && len(in.ID) == 12 && "s"+h[:11] == in.ID {
			delete(s.sessions, h)
			reply(w, map[string]any{"ok": true})
			return
		}
	}
	fail(w, 404, "no such device of yours")
}

// --- sessions and keys (callers hold s.mu)

// startLocked starts a session. A browser has one cookie, so a remembered browser has one session: a new one ends
// the key's older ones, and the devices list never shows one browser twice.
func (s *site) startLocked(addr, bkey, ua string) string {
	if bkey != "" {
		for h, x := range s.sessions {
			if x.key == bkey {
				delete(s.sessions, h)
			}
		}
	}
	if len(ua) > 200 {
		ua = ua[:200]
	}
	b := make([]byte, 32)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	now := s.now()
	s.sessions[hashOf(tok)] = &session{addr: addr, key: bkey, ua: ua, created: now, expires: now.Add(sessionLife)}
	return tok
}

// sessionLocked is the live session the request's cookie names, with its key in the table.
func (s *site) sessionLocked(r *http.Request) (string, *session) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", nil
	}
	h := hashOf(c.Value)
	se := s.sessions[h]
	if se == nil || !s.now().Before(se.expires) {
		return "", nil
	}
	return h, se
}

// forgetLocked forgets a remembered browser and ends every session behind it.
func (s *site) forgetLocked(id string) {
	delete(s.keys, id)
	for h, x := range s.sessions {
		if x.key == id {
			delete(s.sessions, h)
		}
	}
}

func hashOf(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// --- small helpers

// post wraps a POST endpoint: the custom header (a cross-site form cannot send it) and the rate limit.
func (s *site) post(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(header) == "" {
			fail(w, 403, "missing the page's header")
			return
		}
		if !s.allow(r) {
			fail(w, 429, "too many tries; wait a minute")
			return
		}
		h(w, r)
	}
}

// source is who a request comes from, for the phrases and the rate limit: the reader's address (for IPv6, its /64).
// Behind a proxy, take the proxy's word for the reader's address here instead.
func source(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	return gnosignin.SourceOf(ip)
}

// allow is a sliding minute of attempts per source.
func (s *site) allow(r *http.Request) bool {
	ip := source(r)
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var keep []time.Time
	for _, t := range s.tries[ip] {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	if len(keep) >= triesPerMin {
		s.tries[ip] = keep
		return false
	}
	s.tries[ip] = append(keep, now)
	return true
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func setCookie(w http.ResponseWriter, r *http.Request, tok string) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", MaxAge: int(sessionLife / time.Second), HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteLaxMode})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(v); err != nil {
		fail(w, 400, "the request is not the JSON expected")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func reply(w http.ResponseWriter, v any) { writeJSON(w, 200, v) }
func fail(w http.ResponseWriter, code int, e string) {
	writeJSON(w, code, map[string]string{"error": e})
}
