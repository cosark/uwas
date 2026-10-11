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

// F8830: "Header set ... env=VAR" must reach only requests where the variable
// is set (and "env=!VAR" only where it is not); the condition used to be
// dropped so a CORS header meant for one origin went to every client.
func TestHtaccessHeaderEnvConditionDecidedPerRequest(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("hi"), 0o644)
	os.WriteFile(filepath.Join(dir, ".htaccess"), []byte(
		"SetEnvIf Origin \"^https://good\\.example$\" CORS_OK\n"+
			"Header set Access-Control-Allow-Origin \"*\" env=CORS_OK\n"+
			"Header set X-Not-Marked yes env=!CORS_OK\n"+
			"Header set X-Control ok\n"), 0o644)
	cfg := &config.Config{Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{{Host: "h.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"},
			Htaccess: config.HtaccessConfig{Mode: "import"}}}}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	get := func(origin string) http.Header {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "h.test"
		req.RemoteAddr = "192.0.2.5:1"
		req.Header.Set("User-Agent", "uwas-test")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec.Header()
	}
	good, evil := get("https://good.example"), get("https://evil.example")
	if good.Get("X-Control") != "ok" || evil.Get("X-Control") != "ok" {
		t.Fatal("control: unconditional Header rule not applied")
	}
	if good.Get("Access-Control-Allow-Origin") != "*" || good.Get("X-Not-Marked") != "" {
		t.Errorf("allowed origin: ACAO=%q X-Not-Marked=%q, want * and none",
			good.Get("Access-Control-Allow-Origin"), good.Get("X-Not-Marked"))
	}
	if evil.Get("Access-Control-Allow-Origin") != "" || evil.Get("X-Not-Marked") != "yes" {
		t.Errorf("other origin: ACAO=%q X-Not-Marked=%q, want none and yes",
			evil.Get("Access-Control-Allow-Origin"), evil.Get("X-Not-Marked"))
	}
}
