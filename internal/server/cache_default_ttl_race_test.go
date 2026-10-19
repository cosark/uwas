package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F20700: the cache-store path read global.cache.default_ttl straight off the
// live config while reload() overwrites that struct under the config lock, so a
// reload landing during a cache miss was a data race (the stale-hit refresh
// path had the same unlocked read). The reader here goes through the real
// request path; the writer mutates the field exactly as reload's in-place
// config swap does, under cfgMu. Run under -race.
func TestCacheStoreReadsDefaultTTLUnderConfigLock(t *testing.T) {
	dir := t.TempDir()
	const files = 40
	for i := 0; i < files; i++ {
		os.WriteFile(filepath.Join(dir, "f"+strconv.Itoa(i)+".txt"), []byte("hello"), 0o644)
	}
	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text",
			Cache: config.CacheConfig{Enabled: true, DefaultTTL: 30, MemoryLimit: config.ByteSize(4 << 20), DiskPath: t.TempDir(), DiskLimit: config.ByteSize(4 << 20)}},
		Domains: []config.Domain{{Host: "h.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"},
			Cache: config.DomainCache{Enabled: true}}},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()

	// control: a miss then a hit works and the entry is stored.
	get := func(i int) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/f"+strconv.Itoa(i)+".txt", nil)
		req.Host = "h.test"
		req.RemoteAddr = "192.0.2.5:1"
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec
	}
	get(0)
	if got := get(0).Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("control failed: second request X-Cache=%q, want HIT", got)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			mu := s.cfgMu()
			mu.Lock()
			s.config.Global.Cache.DefaultTTL = 30 + i%2
			mu.Unlock()
		}
	}()
	for i := 1; i < files; i++ {
		get(i)
	}
	close(stop)
	wg.Wait()
}
