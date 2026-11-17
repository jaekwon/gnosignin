package gnosignin

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// The browser half is served whole, as a script, and offers what the README says it offers.
func TestServeJS(t *testing.T) {
	w := httptest.NewRecorder()
	ServeJS(w, httptest.NewRequest("GET", "/gnosignin.js", nil))
	if w.Code != 200 || w.Header().Get("Content-Type") != "text/javascript; charset=utf-8" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("served %d %v", w.Code, w.Header())
	}
	body := w.Body.String()
	if body != string(JS) || len(body) < 1000 {
		t.Fatalf("not the whole script: %d bytes", len(body))
	}
	for _, name := range []string{"configure", "connect", "prove", "refusal", "remember", "keyMake", "keyGet", "keyPut", "keyDrop", "keySignIn", "markSignedOut", "signedOutOnPurpose", "signBytesOf"} {
		if !strings.Contains(body, "  return { ") || !strings.Contains(body[strings.LastIndex(body, "return { "):], name) {
			t.Errorf("gnosignin.%s is not offered", name)
		}
	}
	// the key never leaves the browser: made not extractable, and nothing exports the private half
	if !strings.Contains(body, "generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false,") || strings.Contains(body, "exportKey('pkcs8'") || strings.Contains(body, "exportKey('jwk'") {
		t.Error("the browser key is made extractable, or its private half is exported")
	}
}
