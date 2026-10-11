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

// F5700: the request ID is stamped on the shared response header map before the
// cache snapshots it, so a stored entry carried the first visitor's ID and every
// cache hit replayed it, breaking log correlation and leaking one client's ID
// to the next.
func TestCacheHitKeepsOwnRequestID(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644)
	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text",
			Cache: config.CacheConfig{Enabled: true, MemoryLimit: config.ByteSize(4 << 20), DiskPath: t.TempDir(), DiskLimit: config.ByteSize(4 << 20)}},
		Domains: []config.Domain{{Host: "h.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"},
			Cache: config.DomainCache{Enabled: true, TTL: 60}}},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	get := func(rid, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/a.txt", nil)
		req.Host = "h.test"
		req.RemoteAddr = "192.0.2.5:1"
		req.Header.Set("User-Agent", "uwas-test")
		req.Header.Set("X-Request-ID", rid)
		req.Header.Set("Origin", origin)
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec
	}
	first := get("req-one", "https://a.example")
	second := get("req-two", "https://b.example")
	t.Logf("first:  X-Cache=%q rid=%q", first.Header().Get("X-Cache"), first.Header().Get("X-Request-ID"))
	t.Logf("second: X-Cache=%q rid=%q", second.Header().Get("X-Cache"), second.Header().Get("X-Request-ID"))
	// control: the first (cold) response carries its own values
	if first.Header().Get("X-Request-ID") != "req-one" {
		t.Fatalf("control failed: cold response headers wrong")
	}
	if second.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("control failed: second request not a cache HIT (%q)", second.Header().Get("X-Cache"))
	}
	if got := second.Header().Get("X-Request-ID"); got != "req-two" {
		t.Errorf("X-Request-ID on hit = %q, want req-two (another request's ID was replayed)", got)
	}
}
