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

// F9600: an ErrorDocument in a sub-directory's .htaccess applies to failures
// inside that directory (the deepest file wins); the document root's file alone
// used to be read, so the sub-directory's page and quoted text were ignored.
func TestHtaccessErrorDocumentFromSubdirectory(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "uploads", "errors"), 0o755)
	os.MkdirAll(filepath.Join(dir, "errors"), 0o755)
	os.WriteFile(filepath.Join(dir, "errors", "403.html"), []byte("ROOT-403-PAGE"), 0o644)
	os.WriteFile(filepath.Join(dir, "errors", "404.html"), []byte("ROOT-404-PAGE"), 0o644)
	os.WriteFile(filepath.Join(dir, ".htaccess"),
		[]byte("ErrorDocument 403 /errors/403.html\nErrorDocument 404 /errors/404.html\n<Files priv.txt>\nRequire all denied\n</Files>\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "uploads", "errors", "403.html"), []byte("UPLOADS-403-PAGE"), 0o644)
	os.WriteFile(filepath.Join(dir, "uploads", "secret.txt"), []byte("s"), 0o644)
	os.WriteFile(filepath.Join(dir, "uploads", ".htaccess"),
		[]byte("Require all denied\nErrorDocument 403 /uploads/errors/403.html\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "priv.txt"), []byte("p"), 0o644)

	cfg := &config.Config{
		Global:  config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{{Host: "e.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"}}},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	get := func(p string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Host = "e.test"
		req.RemoteAddr = "192.0.2.1:1"
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	// Control: a failure at the root uses the root's page.
	if st, body := get("/priv.txt"); st != 403 || body != "ROOT-403-PAGE" {
		t.Fatalf("root 403 = %d %q, want 403 ROOT-403-PAGE", st, body)
	}
	// The deepest file wins for a code it names.
	if st, body := get("/uploads/secret.txt"); st != 403 || body != "UPLOADS-403-PAGE" {
		t.Errorf("uploads 403 = %d %q, want 403 UPLOADS-403-PAGE", st, body)
	}
	// A code the sub-directory does not name falls back to the root's page.
	if st, body := get("/uploads/missing.txt"); st != 404 || body != "ROOT-404-PAGE" {
		t.Errorf("uploads 404 = %d %q, want 404 ROOT-404-PAGE (inherited)", st, body)
	}
}

// A quoted ErrorDocument text in a sub-directory is the body for that code.
func TestHtaccessErrorTextFromSubdirectory(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	os.WriteFile(filepath.Join(dir, "sub", ".htaccess"), []byte("ErrorDocument 404 \"SUB-404-TEXT\"\n"), 0o644)
	cfg := &config.Config{
		Global:  config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{{Host: "e.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"}}},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	req := httptest.NewRequest(http.MethodGet, "/sub/none.txt", nil)
	req.Host = "e.test"
	req.RemoteAddr = "192.0.2.1:1"
	req.Header.Set("User-Agent", "uwas-test")
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	if rec.Code != 404 || rec.Body.String() != "SUB-404-TEXT" {
		t.Errorf("sub 404 = %d %q, want 404 SUB-404-TEXT", rec.Code, rec.Body.String())
	}
}
