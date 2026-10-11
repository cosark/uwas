package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/cache"
	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F14701: an ESI fragment was served into an unbounded recorder and read back
// with io.ReadAll, so a page that included a large file buffered it twice
// before the page budget was consulted. A fragment over the budget is refused
// as it is written.
func TestESIFragmentIsCappedAtThePageBudget(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, size int64) {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		f.Truncate(size)
		f.Close()
	}
	mk("exact.html", int64(cache.ESIMaxOutputBytes))
	mk("over.html", int64(cache.ESIMaxOutputBytes)+1)
	mk("huge.html", 48<<20)
	os.WriteFile(filepath.Join(dir, "small.html"), []byte("SMALLFRAG"), 0o644)

	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{{Host: "esi.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"},
			Cache: config.DomainCache{Enabled: true, TTL: 60, ESI: true}}},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()

	parent := httptest.NewRequest(http.MethodGet, "/page.html", nil)
	parent.RemoteAddr = "192.0.2.5:1"
	parent.Header.Set("User-Agent", "uwas-test")

	if body, status, _, err := s.FetchFragment("esi.test", "/small.html", parent); err != nil || status != 200 || string(body) != "SMALLFRAG" {
		t.Fatalf("control: small fragment status=%d err=%v body=%q", status, err, body)
	}
	if body, _, _, err := s.FetchFragment("esi.test", "/exact.html", parent); err != nil || len(body) != cache.ESIMaxOutputBytes {
		t.Errorf("a fragment of exactly the budget: len=%d err=%v, want it returned", len(body), err)
	}
	if body, _, _, err := s.FetchFragment("esi.test", "/over.html", parent); err == nil {
		t.Errorf("a fragment one byte over the budget was returned (%d bytes)", len(body))
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	body, _, _, err := s.FetchFragment("esi.test", "/huge.html", parent)
	runtime.ReadMemStats(&after)
	if err == nil || body != nil {
		t.Errorf("a 48 MiB fragment was returned: len=%d err=%v", len(body), err)
	}
	// It was 238 MiB before the cap (476 MiB under -race); the cap buffers at
	// most the budget, which buffer growth doubles (16 MiB, 32 MiB under -race).
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 64<<20 {
		t.Errorf("refusing a 48 MiB fragment allocated %d MiB", alloc>>20)
	}
}
