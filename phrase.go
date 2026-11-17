package gnosignin

// The phrases a site hands out to be signed, each signed once.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// Life is how long a wallet's phrase lasts: long enough to find the wallet's window and approve on a Ledger,
	// short enough that a stolen phrase is stale.
	Life = 10 * time.Minute
	// KeyLife is how long a browser key's phrase lasts: the page's own code signs it at once.
	KeyLife = 2 * time.Minute
	// MaxOutstanding is how many phrases a Challenges keeps at once.
	MaxOutstanding = 4096
	// MaxPerSource is how many phrases one source (a reader's address) holds at once; past it, its oldest goes. So a
	// flood from a few addresses cannot crowd everyone else out: it would take MaxOutstanding/MaxPerSource of them.
	MaxPerSource = 16
)

// KindKey is the purpose of a phrase a remembered browser's own key signs. A wallet's phrase has no kind.
const KindKey = "key"

// Challenges holds the phrases handed out and not yet answered. It is safe for concurrent use.
type Challenges struct {
	mu     sync.Mutex
	at     map[string]rec
	counts map[string]int            // outstanding phrases per source
	Rand   func([]byte) (int, error) // where the ids and nonces come from; crypto/rand unless a test says otherwise
}

type rec struct {
	Phrase
	from string
	at   time.Time
}

// A Phrase is what a site asked a browser to sign: the words, what they are for (Kind: "" for a wallet's sign-in,
// KindKey for a remembered browser's), and the browser key a wallet's sign-in vouches for ("" for none).
type Phrase struct {
	Words, Kind, Key string
}

// NewChallenges is an empty Challenges.
func NewChallenges() *Challenges {
	return &Challenges{at: map[string]rec{}, counts: map[string]int{}, Rand: rand.Read}
}

// Issue hands out a phrase for a wallet's sign-in under a fresh id. The phrase is read in the wallet's approval
// window, so it says which site asks and what the signature does. from is who asks: the reader's address, say
// (for IPv6, its /64), for MaxPerSource.
func (c *Challenges) Issue(from, site string, now time.Time) (id, words string, err error) {
	return c.IssueFor(from, site, "", "", now)
}

// IssueFor is Issue for a purpose. With a key (a KeyRE id) the wallet's phrase names that browser key, so the one
// signature signs in and vouches for that key and no other. Kind KindKey is the phrase a remembered browser's own
// key signs, worded apart so that neither can pass for the other.
func (c *Challenges) IssueFor(from, site, kind, key string, now time.Time) (id, words string, err error) {
	var b [24]byte
	if _, err := c.Rand(b[:]); err != nil {
		return "", "", err
	}
	id = hex.EncodeToString(b[:8])
	nonce := base64.RawURLEncoding.EncodeToString(b[8:])
	switch {
	case kind == KindKey:
		key = ""
		words = site + ": this browser signs in with the key it keeps · " + nonce
	case kind != "":
		return "", "", errors.New("no such phrase")
	case key != "" && !KeyRE.MatchString(key):
		return "", "", errors.New("that is not a browser key")
	case key != "":
		words = site + ": sign in with this wallet and remember this browser (key " + key + ") · " + nonce
	default:
		words = site + ": sign in with this wallet · " + nonce
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts[from] >= MaxPerSource { // this source's oldest goes; nobody else's
		oldest, at := "", now
		for k, v := range c.at {
			if v.from == from && !v.at.After(at) {
				oldest, at = k, v.at
			}
		}
		c.dropLocked(oldest)
	}
	if len(c.at) >= MaxOutstanding {
		for k, v := range c.at {
			if now.Sub(v.at) > Life {
				c.dropLocked(k)
			}
		}
		if len(c.at) >= MaxOutstanding {
			return "", "", errors.New("too many sign-ins at once; try again in a minute")
		}
	}
	c.at[id] = rec{Phrase{Words: words, Kind: kind, Key: key}, from, now}
	c.counts[from]++
	return id, words, nil
}

// SourceOf is the source MaxPerSource counts, from a reader's address: the address itself, or for IPv6 its /64,
// since one machine can hold a whole /64.
func SourceOf(ip string) string {
	a := net.ParseIP(strings.TrimSpace(ip))
	if a == nil {
		return ip
	}
	if a.To4() != nil {
		return a.To4().String()
	}
	return a.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// dropLocked forgets one phrase; the caller holds c.mu.
func (c *Challenges) dropLocked(id string) {
	r, ok := c.at[id]
	if !ok {
		return
	}
	delete(c.at, id)
	if c.counts[r.from]--; c.counts[r.from] <= 0 {
		delete(c.counts, r.from)
	}
}

// Take returns the words under an id and FORGETS them: one phrase answers once. fresh says it is still in its life.
func (c *Challenges) Take(id string, now time.Time) (words string, fresh bool) {
	p, fresh := c.TakePhrase(id, now)
	return p.Words, fresh
}

// TakePhrase is Take with what the phrase was for; an unknown id answers an empty Phrase. A key's phrase is fresh
// for KeyLife, a wallet's for Life.
func (c *Challenges) TakePhrase(id string, now time.Time) (Phrase, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.at[id]
	if !ok {
		return Phrase{}, false
	}
	c.dropLocked(id)
	life := Life
	if r.Kind == KindKey {
		life = KeyLife
	}
	return r.Phrase, now.Sub(r.at) <= life
}
