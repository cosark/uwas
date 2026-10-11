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

// F9104: Header directives of a subdirectory's .htaccess reach the files under
// it, after (and overriding) the document root's, and not the files outside it.
func TestHtaccessSubdirectoryHeaders(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"uploads", "uploads/deep", "other"} {
		os.MkdirAll(filepath.Join(dir, sub), 0o755)
	}
	for _, f := range []string{"top.txt", "uploads/f.txt", "uploads/deep/g.txt", "other/o.txt"} {
		os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644)
	}
	os.WriteFile(filepath.Join(dir, ".htaccess"), []byte(
		"SetEnvIf User-Agent \"uwas-test\" TESTER\nHeader set X-Root root\nHeader set X-Layer root\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "uploads", ".htaccess"), []byte(
		"Header set Content-Security-Policy \"default-src 'none'\"\nHeader set X-Layer uploads\n"+
			"Header set X-Tester yes env=TESTER\n<FilesMatch \"\\.txt$\">\nHeader set X-Txt scoped\n</FilesMatch>\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "uploads", "deep", ".htaccess"), []byte("Header set X-Layer deep\n"), 0o644)
	cfg := &config.Config{Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{{Host: "d.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"},
			Htaccess: config.HtaccessConfig{Mode: "import"}}}}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	get := func(p string) http.Header {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Host = "d.test"
		req.RemoteAddr = "192.0.2.5:1"
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec.Header()
	}
	top, up, deep, other := get("/top.txt"), get("/uploads/f.txt"), get("/uploads/deep/g.txt"), get("/other/o.txt")
	for name, h := range map[string]http.Header{"top": top, "uploads": up, "deep": deep, "other": other} {
		if h.Get("X-Root") != "root" {
			t.Fatalf("control: %s lost the root header", name)
		}
	}
	if up.Get("Content-Security-Policy") == "" || up.Get("X-Layer") != "uploads" || up.Get("X-Txt") != "scoped" {
		t.Errorf("uploads: CSP=%q X-Layer=%q X-Txt=%q, want set, uploads, scoped", up.Get("Content-Security-Policy"), up.Get("X-Layer"), up.Get("X-Txt"))
	}
	if up.Get("X-Tester") != "yes" {
		t.Errorf("env set at the root must govern a subdirectory's env= header, got %q", up.Get("X-Tester"))
	}
	if deep.Get("X-Layer") != "deep" || deep.Get("Content-Security-Policy") == "" {
		t.Errorf("deep: X-Layer=%q CSP=%q, want deep and inherited CSP", deep.Get("X-Layer"), deep.Get("Content-Security-Policy"))
	}
	for name, h := range map[string]http.Header{"top": top, "other": other} {
		if h.Get("Content-Security-Policy") != "" || h.Get("X-Layer") != "root" || h.Get("X-Txt") != "" {
			t.Errorf("%s must keep only the root's headers: CSP=%q X-Layer=%q X-Txt=%q", name, h.Get("Content-Security-Policy"), h.Get("X-Layer"), h.Get("X-Txt"))
		}
	}
}
