package server

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// The background refresh must ask the origin on the scheme of the request that
// found the entry stale. Run as plain HTTP, an origin that redirects http to
// https answered it with a 301 that was stored under the key HTTPS visitors
// read, so every later HTTPS request was redirected to itself (F5400).
func TestStaleRevalidateKeepsRequestScheme(t *testing.T) {
	var refreshes atomic.Int64
	var lastProto atomic.Value
	lastProto.Store("")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshes.Add(1)
		lastProto.Store(r.Header.Get("X-Forwarded-Proto"))
		if r.Header.Get("X-Forwarded-Proto") != "https" {
			http.Redirect(w, r, "https://secure.test/", http.StatusMovedPermanently)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "page")
	}))
	t.Cleanup(origin.Close)

	cfg := &config.Config{
		Global: config.GlobalConfig{
			WorkerCount: "1", LogLevel: "error", LogFormat: "text",
			Cache: config.CacheConfig{Enabled: true, MemoryLimit: config.ByteSize(8 << 20),
				DefaultTTL: 1, GraceTTL: 60, StaleWhileRevalidate: true},
		},
		Domains: []config.Domain{{
			Host: "secure.test", Type: "proxy", Root: t.TempDir(),
			SSL:   config.SSLConfig{Mode: "off"},
			Cache: config.DomainCache{Enabled: true, TTL: 1},
			Proxy: config.ProxyConfig{Upstreams: []config.Upstream{{Address: origin.URL, Weight: 1}}},
		}},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel() })

	get := func() (int, string) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = "secure.test"
		req.TLS = &tls.ConnectionState{}
		s.handleRequest(rec, req)
		return rec.Code, rec.Body.String()
	}

	if code, body := get(); code != 200 || body != "page" {
		t.Fatalf("first HTTPS request: code=%d body=%q, want 200 page", code, body)
	}
	time.Sleep(1100 * time.Millisecond) // past TTL, inside grace
	get()                               // stale hit schedules the refresh
	waitFor(t, "the background refresh to reach the origin", func() bool { return refreshes.Load() >= 2 })
	if p := lastProto.Load().(string); p != "https" {
		t.Errorf("refresh reached the origin with X-Forwarded-Proto=%q, want https", p)
	}
	// Let the refresh store its result before reading it back.
	waitFor(t, "the refresh to finish", func() bool {
		busy := false
		s.revalidating.Range(func(_, _ any) bool { busy = true; return false })
		return !busy
	})
	if code, body := get(); code != 200 || body != "page" {
		t.Errorf("HTTPS request after the refresh: code=%d body=%q, want 200 page", code, body)
	}
}
