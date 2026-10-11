package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F15001: a background refresh runs after its request has finished, so it sat
// outside every per-request limit; one stale entry per distinct URL meant one
// origin request per URL, all at the same moment. The number in flight is now
// capped, and an entry that was skipped is refreshed by a later request.
func TestRevalidateConcurrencyIsCapped(t *testing.T) {
	const keys = 200
	var inflight, peak atomic.Int64
	release := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.UserAgent(), "UWAS-Revalidate") {
			n := inflight.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			<-release
			inflight.Add(-1)
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "v")
	}))
	defer origin.Close()
	var once sync.Once
	freeAll := func() { once.Do(func() { close(release) }) }
	defer freeAll()

	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text",
			Cache: config.CacheConfig{Enabled: true, MemoryLimit: config.ByteSize(64 << 20), DefaultTTL: 1, GraceTTL: 60, StaleWhileRevalidate: true}},
		Domains: []config.Domain{{Host: "stale.test", Type: "proxy", SSL: config.SSLConfig{Mode: "off"},
			Cache: config.DomainCache{Enabled: true, TTL: 1},
			Proxy: config.ProxyConfig{Upstreams: []config.Upstream{{Address: origin.URL, Weight: 1}}}}},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel() })

	get := func(i int) string {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", fmt.Sprintf("/k/%d", i), nil)
		req.Host = "stale.test"
		s.handleRequest(rec, req)
		return rec.Header().Get("X-Cache")
	}
	for i := 0; i < keys; i++ {
		get(i)
	}
	time.Sleep(1100 * time.Millisecond) // every entry is past its TTL, inside grace
	for i := 0; i < keys; i++ {
		if st := get(i); st != "STALE" {
			t.Fatalf("/k/%d: X-Cache = %q, want STALE", i, st)
		}
	}
	time.Sleep(700 * time.Millisecond) // let the refresh goroutines reach the origin
	if got := peak.Load(); got < 1 || got > 64 {
		t.Errorf("%d background refreshes reached the origin at once for %d stale URLs, want a small bounded number (1..64)", got, keys)
	}

	// Release the origin: the skipped entries must still become fresh through
	// later requests, not stay stale forever.
	freeAll()
	deadline := time.Now().Add(20 * time.Second)
	for {
		stale := 0
		for i := 0; i < keys; i++ {
			if get(i) != "HIT" {
				stale++
			}
		}
		if stale == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d entries never became fresh after the cap lifted", stale, keys)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
