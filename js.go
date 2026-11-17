package gnosignin

import (
	_ "embed"
	"net/http"
)

// JS is the browser half, gnosignin.js, for a site to serve from its own origin.
//
//go:embed gnosignin.js
var JS []byte

// ServeJS serves gnosignin.js: mount it where the page loads it, e.g. mux.HandleFunc("GET /gnosignin.js", ServeJS).
// It is served from the site's own origin, so a page whose Content-Security-Policy allows only 'self' can load it.
func ServeJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-cache") // a deploy's new copy is picked up at once; an unchanged one still revalidates cheaply
	w.Write(JS)
}
