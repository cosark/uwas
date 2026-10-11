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

// F9010: cache.rules[].cache_control and locations[].cache_control are stamped
// before the request is dispatched, so an error the dispatch ends in carried the
// lifetime meant for the page.
func TestOperatorCacheControlNotSentOnErrors(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "assets"), 0o755)
	os.WriteFile(filepath.Join(dir, "assets", "app.css"), []byte("body{}"), 0o644)

	// An upstream address nothing listens on, so the location proxy answers 502.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text",
			Cache: config.CacheConfig{Enabled: true, MemoryLimit: config.ByteSize(4 << 20)}},
		Domains: []config.Domain{{Host: "c.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"},
			Cache: config.DomainCache{Enabled: true, TTL: 60,
				Rules: []config.CacheRule{
					{Match: "/assets/*", CacheControl: "public, max-age=86400"},
					{Match: "/private/*", CacheControl: "no-store"},
				}},
			Locations: []config.LocationConfig{{Match: "/api/", ProxyPass: deadURL, CacheControl: "public, max-age=3600"}},
		}},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	get := func(p string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Host = "c.test"
		req.RemoteAddr = "192.0.2.1:1"
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec.Code, rec.Header().Get("Cache-Control")
	}

	// Control: the success response keeps the operator's value, cold and cached.
	for i := 0; i < 2; i++ {
		if st, cc := get("/assets/app.css"); st != 200 || cc != "public, max-age=86400" {
			t.Fatalf("control request %d: status=%d Cache-Control=%q, want 200 + public, max-age=86400", i+1, st, cc)
		}
	}
	for _, p := range []string{"/assets/missing.css", "/api/x"} {
		st, cc := get(p)
		if st < 400 {
			t.Fatalf("%s: status=%d, want an error status", p, st)
		}
		if cc != "" {
			t.Errorf("%s: error status %d carries Cache-Control %q, want none", p, st, cc)
		}
	}

	// A restrictive value never lengthens how long an error is kept, so it stays.
	if st, cc := get("/private/missing"); st != 404 || cc != "no-store" {
		t.Errorf("/private/missing: status=%d Cache-Control=%q, want 404 + no-store", st, cc)
	}
}
