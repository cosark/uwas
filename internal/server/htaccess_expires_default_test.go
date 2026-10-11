package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F9103: the compact "A<seconds>"/"M<seconds>" forms and an explicit zero
// lifetime are read as written; only an unparsable value falls back to 1 hour.
func TestParseExpiresDurationCompactAndZero(t *testing.T) {
	cases := map[string]string{
		"access plus 1 month":          "2592000",
		"access plus 1 week 2 days":    "777600",
		"A2592000":                     "2592000",
		"a300":                         "300",
		"M86400":                       "86400",
		"access plus 0 seconds":        "0",
		"":                             "3600",
		"access plus soon":             "3600",
		"access plus 2 fortnights":     "3600",
		"modification plus 10 minutes": "600",
	}
	for in, want := range cases {
		if got := parseExpiresDuration(in); got != want {
			t.Errorf("parseExpiresDuration(%q) = %q, want %q", in, got, want)
		}
	}
}

// F9102: ExpiresDefault covers every type ExpiresByType does not name.
func TestHtaccessExpiresDefaultAppliesToUnnamedTypes(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.html"), []byte("<p>"), 0o644)
	os.WriteFile(filepath.Join(dir, "a.css"), []byte("b{}"), 0o644)
	os.WriteFile(filepath.Join(dir, ".htaccess"), []byte(
		"ExpiresActive On\nExpiresByType text/html \"access plus 1 hour\"\nExpiresDefault \"access plus 1 month\"\n"), 0o644)
	cfg := &config.Config{Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{{Host: "e.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"},
			Htaccess: config.HtaccessConfig{Mode: "import"}}}}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "e.test"
		req.RemoteAddr = "192.0.2.5:1"
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec
	}
	if got := get("/a.html").Header().Get("Cache-Control"); got != "max-age=3600" {
		t.Errorf("a.html Cache-Control = %q, want ExpiresByType's max-age=3600", got)
	}
	if got := get("/a.css").Header().Get("Cache-Control"); got != "max-age=2592000" {
		t.Errorf("a.css Cache-Control = %q, want ExpiresDefault's max-age=2592000", got)
	}
	if rec := get("/missing.css"); rec.Code != http.StatusNotFound || rec.Header().Get("Cache-Control") == "max-age=2592000" {
		t.Errorf("404 must not be stamped with ExpiresDefault: %d %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
}
