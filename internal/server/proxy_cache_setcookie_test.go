package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F18202: the shared cache refused a response carrying Set-Cookie by looking
// at the first Set-Cookie line only. When that line was empty and a later one
// carried the session, the response was stored and the next visitor was handed
// the first visitor's cookie.
func TestProxyCacheRefusesAnySetCookieLine(t *testing.T) {
	var hits atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		switch r.URL.Path {
		case "/empty-first":
			w.Header()["Set-Cookie"] = []string{"", fmt.Sprintf("sid=visitor%d", n)}
		case "/plain":
			// control: a single Set-Cookie line is never cached
			w.Header().Set("Set-Cookie", fmt.Sprintf("sid=visitor%d", n))
		default:
			w.Header().Set("Cache-Control", "public")
		}
		fmt.Fprintf(w, "body%d", n)
	}))
	defer up.Close()

	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text",
			Cache: config.CacheConfig{Enabled: true, MemoryLimit: config.ByteSize(8 << 20), DefaultTTL: 60}},
		Domains: []config.Domain{{
			Host: "sc.test", Type: "proxy", Root: t.TempDir(), SSL: config.SSLConfig{Mode: "off"},
			Cache: config.DomainCache{Enabled: true, TTL: 60},
			Proxy: config.ProxyConfig{Upstreams: []config.Upstream{{Address: up.URL, Weight: 1}}, AllowPrivateUpstreams: true},
		}},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "sc.test"
		req.RemoteAddr = "192.0.2.5:1"
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec
	}

	// Control: a cacheable path is shared (second request is a hit).
	get("/shared")
	if rec := get("/shared"); rec.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("control premise broken: /shared X-Cache = %q", rec.Header().Get("X-Cache"))
	}
	// Control: a normal Set-Cookie is never replayed.
	get("/plain")
	if rec := get("/plain"); rec.Header().Get("X-Cache") == "HIT" {
		t.Fatalf("control: /plain was served from cache")
	}

	first := get("/empty-first")
	second := get("/empty-first")
	if second.Header().Get("X-Cache") == "HIT" {
		t.Errorf("EXPECTED: a response with a Set-Cookie line is not cached\nACTUAL: second visitor got X-Cache=HIT body %q Set-Cookie %q (first visitor's was %q)",
			second.Body.String(), second.Header().Values("Set-Cookie"), first.Header().Values("Set-Cookie"))
	}
}
