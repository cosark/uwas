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

// F9100/F9101: Header inside <FilesMatch>/<Files> reached no response and
// AddType was ignored; both must follow the requested file.
func TestHtaccessFilesScopedHeaderAndAddType(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"app.js": "1", "a.txt": "t", "logo.vec": "<svg/>", "m.wasm": "w"} {
		os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644)
	}
	os.WriteFile(filepath.Join(dir, ".htaccess"), []byte(
		"Header set X-Control ok\n"+
			"<FilesMatch \"\\.js$\">\nHeader set X-Js scoped\nHeader set X-Only-Marked yes env=!NOPE\n</FilesMatch>\n"+
			"<Files a.txt>\nHeader set X-Txt scoped\n</Files>\n"+
			"AddType image/svg+xml .vec\n"), 0o644)
	cfg := &config.Config{Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{{Host: "f.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"},
			Htaccess: config.HtaccessConfig{Mode: "import"}}}}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "f.test"
		req.RemoteAddr = "192.0.2.5:1"
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec
	}
	js, txt, vec := get("/app.js"), get("/a.txt"), get("/logo.vec")
	if js.Header().Get("X-Control") != "ok" || txt.Header().Get("X-Control") != "ok" {
		t.Fatal("control: unconditional Header rule not applied")
	}
	if js.Header().Get("X-Js") != "scoped" || js.Header().Get("X-Only-Marked") != "yes" {
		t.Errorf("app.js headers X-Js=%q X-Only-Marked=%q, want scoped and yes", js.Header().Get("X-Js"), js.Header().Get("X-Only-Marked"))
	}
	if txt.Header().Get("X-Js") != "" || txt.Header().Get("X-Txt") != "scoped" {
		t.Errorf("a.txt headers X-Js=%q X-Txt=%q, want none and scoped", txt.Header().Get("X-Js"), txt.Header().Get("X-Txt"))
	}
	if got := vec.Header().Get("Content-Type"); got != "image/svg+xml" {
		t.Errorf("logo.vec Content-Type = %q, want image/svg+xml (AddType)", got)
	}
	if got := get("/m.wasm").Header().Get("Content-Type"); got == "image/svg+xml" {
		t.Errorf("m.wasm must keep its own type, got %q", got)
	}
	if missing := get("/missing.vec"); missing.Code != http.StatusNotFound || missing.Header().Get("Content-Type") == "image/svg+xml" {
		t.Errorf("404 for an AddType extension: status %d type %q, want 404 and its own type", missing.Code, missing.Header().Get("Content-Type"))
	}
}
