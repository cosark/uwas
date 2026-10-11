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

// F6000: ExpiresByType ran before the file handler had set Content-Type, so it
// never matched a real static response; Apache also matches the MIME type
// case-insensitively and does not stamp error responses.
func TestHtaccessExpiresByTypeAppliesToStaticResponses(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("<p>x</p>"), 0o644)
	os.WriteFile(filepath.Join(dir, "a.css"), []byte("a{}"), 0o644)
	os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b"), 0o644)
	os.WriteFile(filepath.Join(dir, ".htaccess"), []byte(
		"ExpiresActive On\nExpiresByType text/html \"access plus 1 hour\"\nExpiresByType TEXT/CSS \"access plus 1 day\"\n"), 0o644)
	cfg := &config.Config{Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{{Host: "e.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"},
			Htaccess: config.HtaccessConfig{Mode: "import"}}}}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	get := func(p string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Host = "e.test"
		req.RemoteAddr = "192.0.2.1:1"
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec
	}
	for path, want := range map[string]string{
		"/index.html": "max-age=3600",
		"/a.css":      "max-age=86400",
		"/b.txt":      "", // control: no ExpiresByType entry for text/plain
	} {
		rec := get(path)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		if got := rec.Header().Get("Cache-Control"); got != want {
			t.Errorf("%s Cache-Control = %q, want %q", path, got, want)
		}
	}
	if rec := get("/missing.html"); rec.Code != http.StatusNotFound || rec.Header().Get("Cache-Control") == "max-age=3600" {
		t.Errorf("404 response: status %d Cache-Control %q, want no Expires stamp", rec.Code, rec.Header().Get("Cache-Control"))
	}
}
