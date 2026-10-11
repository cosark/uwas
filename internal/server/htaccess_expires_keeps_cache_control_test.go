package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F6300: ExpiresByType (F6000) overwrote the Cache-Control a proxied or
// operator-configured response already carried, so a "private, no-store"
// page became cacheable for an hour.
func TestHtaccessExpiresKeepsExistingCacheControl(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/private" {
			w.Header().Set("Cache-Control", "private, no-store")
		}
		fmt.Fprint(w, "page")
	}))
	defer origin.Close()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".htaccess"), []byte(
		"ExpiresActive On\nExpiresByType text/html \"access plus 1 hour\"\n"), 0o644)
	cfg := &config.Config{Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{{Host: "p.test", Type: "proxy", Root: dir, SSL: config.SSLConfig{Mode: "off"},
			Htaccess: config.HtaccessConfig{Mode: "import"},
			Proxy:    config.ProxyConfig{Upstreams: []config.Upstream{{Address: origin.URL, Weight: 1}}}}}}
	s := New(cfg, logger.New("error", "text"))
	defer func() { s.cancel(); time.Sleep(50 * time.Millisecond) }()
	s.handler = s.buildMiddlewareChain()
	get := func(p string) string {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Host = "p.test"
		req.RemoteAddr = "192.0.2.1:1"
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec.Header().Get("Cache-Control")
	}
	if ctrl := get("/public"); ctrl != "max-age=3600" {
		t.Fatalf("control: Cache-Control = %q, want max-age=3600", ctrl)
	}
	if got := get("/private"); got != "private, no-store" {
		t.Errorf("Cache-Control = %q, want the application's private, no-store", got)
	}
}
