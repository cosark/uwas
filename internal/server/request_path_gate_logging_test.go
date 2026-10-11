package server

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F14702: the 414 gate runs ahead of the access log, so a refused over-long
// path was neither logged nor counted. It is counted every time and logged at
// most once a second, with the start of the path and the number held back.
func TestRequestPathGateCountsAndLogsRefusals(t *testing.T) {
	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "debug", LogFormat: "text"},
		Domains: []config.Domain{{Host: "p.test", Type: "static", Root: t.TempDir(),
			SSL: config.SSLConfig{Mode: "off"}}},
	}
	lg := logger.New("debug", "text")
	var buf bytes.Buffer
	lg.Logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s := New(cfg, lg)
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()

	do := func(path string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.URL.Path = path
		req.Host = "p.test"
		req.RemoteAddr = "192.0.2.77:1234"
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec.Code
	}
	lines := func() int { return strings.Count(buf.String(), "request path too long") }

	// Control: an ordinary request is counted once and does not trip the gate.
	before := s.metrics.RequestsTotal.Load()
	if c := do("/missing"); c != http.StatusNotFound {
		t.Fatalf("control status %d", c)
	}
	if got := s.metrics.RequestsTotal.Load() - before; got != 1 {
		t.Fatalf("control request counted %d times", got)
	}
	if lines() != 0 {
		t.Fatalf("an ordinary request logged a 414 line: %s", buf.String())
	}

	long := "/" + strings.Repeat("a", 200000)
	before = s.metrics.RequestsTotal.Load()
	for i := 0; i < 3; i++ {
		if c := do(long); c != http.StatusRequestURITooLong {
			t.Fatalf("status %d for an over-long path, want 414", c)
		}
	}
	if got := s.metrics.RequestsTotal.Load() - before; got != 3 {
		t.Errorf("3 refused requests counted %d times", got)
	}
	if got := lines(); got != 1 {
		t.Errorf("3 refusals in a burst logged %d lines, want 1", got)
	}
	out := buf.String()
	if !strings.Contains(out, "192.0.2.77") {
		t.Errorf("log line misses the client address: %s", out)
	}
	if len(out) > 2000 {
		t.Errorf("log output is %d bytes: the 200 KB path was not clipped", len(out))
	}

	// A second later the next refusal is logged and reports the two held back.
	s.longPathLogAt.Store(time.Now().Add(-2 * time.Second).UnixNano())
	do(long)
	if got := lines(); got != 2 {
		t.Fatalf("%d lines after the interval, want 2", got)
	}
	if !strings.Contains(buf.String(), "suppressed=2") {
		t.Errorf("second line does not report 2 suppressed refusals: %s", buf.String())
	}
}
