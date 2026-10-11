package server

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F13200: a HEAD response carries no body, so it is not billed against the
// domain's bandwidth limit. Handlers still write one (error pages, PHP output)
// and net/http discards it, so the writer's byte count is not traffic; billing
// it let a stream of HEADs fill the quota and block the domain.
func TestHeadRequestsAreNotBilledAsBandwidth(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "404.html"), []byte(strings.Repeat("N", 100_000)), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{{
			Host: "bw.test", Root: root, Type: "static", SSL: config.SSLConfig{Mode: "off"},
			ErrorPages: map[int]string{404: "404.html"},
			Bandwidth:  config.BandwidthConfig{Enabled: true, MonthlyLimit: 1 << 20, Action: "block"},
		}},
	}
	s := New(cfg, logger.New("error", "text"))
	s.handler = s.buildMiddlewareChain()
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })

	do := func(method, path string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		req.Host = "bw.test"
		req.RemoteAddr = "198.51.100.7:1"
		req.Header.Set("User-Agent", "uwas-test")
		s.handler.ServeHTTP(rec, req)
		return rec.Code
	}
	used := func() int64 {
		st := s.bwMgr.GetStatus("bw.test")
		if st == nil {
			t.Fatal("no bandwidth status for bw.test")
		}
		return st.MonthlyBytes
	}

	// Control: a GET miss serves the page and is billed for it.
	if code := do("GET", "/missing-get"); code != 404 {
		t.Fatalf("GET miss status = %d, want 404", code)
	}
	afterGet := used()
	if afterGet < 100_000 {
		t.Fatalf("GET miss billed %d bytes, want at least the 100000-byte page", afterGet)
	}

	for i := 0; i < 20; i++ {
		do("HEAD", "/missing-head")
	}
	if got := used() - afterGet; got != 0 {
		t.Errorf("20 HEAD requests billed %d bytes, want 0 (no body is sent)", got)
	}
	if s.bwMgr.IsBlocked("bw.test") {
		t.Error("HEAD requests blocked the domain")
	}
	// The limit still engages for real traffic.
	for i := 0; i < 11; i++ {
		do("GET", "/missing-get")
	}
	if !s.bwMgr.IsBlocked("bw.test") {
		t.Error("GET traffic past the limit did not block the domain")
	}
}
