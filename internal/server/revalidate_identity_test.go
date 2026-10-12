package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/cache"
	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F17800: the background refresh asked the origin as 127.0.0.1, an identity
// origins routinely trust ("local" debug/admin views, loopback-only content).
// The answer was stored under the key every visitor reads.
func TestRevalidateDoesNotAskOriginAsLoopback(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		ip := r.Header.Get("X-Real-IP")
		if strings.HasPrefix(ip, "127.") || strings.HasPrefix(r.Header.Get("X-Forwarded-For"), "127.") {
			fmt.Fprint(w, "LOCAL-ONLY-VIEW")
			return
		}
		fmt.Fprint(w, "PUBLIC-VIEW")
	}))
	t.Cleanup(origin.Close)

	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text",
			Cache: config.CacheConfig{Enabled: true, MemoryLimit: config.ByteSize(8 << 20),
				DefaultTTL: 1, GraceTTL: 60, StaleWhileRevalidate: true}},
		Domains: []config.Domain{{
			Host: "id.test", Type: "proxy", Root: t.TempDir(), SSL: config.SSLConfig{Mode: "off"},
			Cache: config.DomainCache{Enabled: true, TTL: 1},
			Proxy: config.ProxyConfig{Upstreams: []config.Upstream{{Address: origin.URL, Weight: 1}}},
		}},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel() })

	get := func(remote string) (string, string) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = "id.test"
		req.RemoteAddr = remote + ":4000"
		s.handleRequest(rec, req)
		return rec.Header().Get("X-Cache"), rec.Body.String()
	}
	if _, b := get("203.0.113.9"); b != "PUBLIC-VIEW" {
		t.Fatalf("control premise broken: fill = %q", b)
	}
	time.Sleep(1100 * time.Millisecond) // past TTL, inside grace
	if st, _ := get("203.0.113.9"); st != cache.StatusStale {
		t.Fatalf("X-Cache = %q, want STALE", st)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && s.revalActive.Load() > 0 {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if st, b := get("198.51.100.7"); b != "PUBLIC-VIEW" {
		t.Errorf("an external visitor got %q (X-Cache=%q) after a background refresh; the refresh asked the origin as loopback", b, st)
	}
}

// A directory restricted to a client range must still be refreshed for that
// range: asked as loopback, the refresh was denied and the entry purged.
func TestRevalidateKeepsIPRestrictedEntryFresh(t *testing.T) {
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "in"), 0o755))
	must(os.WriteFile(filepath.Join(root, "in/.htaccess"), []byte("Require ip 10.0.0.0/8\n"), 0o644))
	file := filepath.Join(root, "in/a.txt")
	must(os.WriteFile(file, []byte("v1"), 0o644))
	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text",
			Cache: config.CacheConfig{Enabled: true, MemoryLimit: config.ByteSize(8 << 20),
				DefaultTTL: 1, GraceTTL: 60, StaleWhileRevalidate: true}},
		Domains: []config.Domain{{Host: "ip.test", Type: "static", Root: root, SSL: config.SSLConfig{Mode: "off"},
			Cache: config.DomainCache{Enabled: true, TTL: 1}}},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel() })
	get := func(remote string) (string, string) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/in/a.txt", nil)
		req.Host = "ip.test"
		req.RemoteAddr = remote + ":4000"
		s.handleRequest(rec, req)
		return rec.Header().Get("X-Cache"), rec.Body.String()
	}
	if _, b := get("10.1.2.3"); b != "v1" {
		t.Fatalf("control premise broken: fill = %q", b)
	}
	must(os.WriteFile(file, []byte("v2"), 0o644))
	time.Sleep(1100 * time.Millisecond)
	if st, _ := get("10.1.2.3"); st != cache.StatusStale {
		t.Fatalf("X-Cache = %q, want STALE", st)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, b := get("10.1.2.3"); b == "v2" {
			if _, b := get("203.0.113.9"); strings.Contains(b, "v") && !strings.Contains(b, "403") {
				t.Errorf("a denied client got %q from the refreshed entry", b)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("the entry was never refreshed to v2 for the allowed client")
}
