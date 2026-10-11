package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

func htaccessLevelServer(t *testing.T, host, dir string) func(path string) *httptest.ResponseRecorder {
	t.Helper()
	cfg := &config.Config{Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{{Host: host, Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"},
			Htaccess: config.HtaccessConfig{Mode: "import"}}}}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	return func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = host
		req.RemoteAddr = "192.0.2.5:1"
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec
	}
}

func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(dir, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// F9401: ErrorDocument 404 "message" is the response body, not a file name.
func TestHtaccessErrorDocumentQuotedText(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"gone.html": "GONE-PAGE",
		".htaccess": "ErrorDocument 404 \"Custom not found message\"\nErrorDocument 410 /gone.html\nRedirect gone /old\n",
	})
	get := htaccessLevelServer(t, "e.test", dir)
	if ctl := get("/old"); ctl.Code != http.StatusGone || !strings.Contains(ctl.Body.String(), "GONE-PAGE") {
		t.Fatalf("control: file-form ErrorDocument gave %d %q", ctl.Code, ctl.Body.String())
	}
	if r := get("/missing"); r.Code != http.StatusNotFound || !strings.Contains(r.Body.String(), "Custom not found message") {
		t.Errorf("/missing = %d %q, want 404 with the message", r.Code, r.Body.String())
	}
}

// F9402: AddType / ExpiresDefault / DirectoryIndex / ExpiresActive Off in a
// sub-directory .htaccess apply below it; they used to be read from the
// document root's file only, and not at all when only a sub-directory had one.
func TestHtaccessSubdirectorySettingsApply(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"b.rt":              "root-typed",
		"uploads/a.foo":     "foo",
		"uploads/home.txt":  "SUBDIR-INDEX",
		"plain/x.txt":       "x",
		"quiet/x.txt":       "x",
		".htaccess":         "AddType application/x-root .rt\nExpiresActive On\nExpiresByType text/plain \"access plus 1 hour\"\n",
		"uploads/.htaccess": "AddType application/x-foo .foo\nExpiresDefault \"access plus 1 day\"\nDirectoryIndex home.txt\n",
		"quiet/.htaccess":   "ExpiresActive Off\n",
	})
	get := htaccessLevelServer(t, "d.test", dir)
	if got := get("/b.rt").Header().Get("Content-Type"); got != "application/x-root" {
		t.Fatalf("control: root AddType = %q", got)
	}
	if got := get("/plain/x.txt").Header().Get("Cache-Control"); got != "max-age=3600" {
		t.Fatalf("control: root ExpiresByType = %q", got)
	}
	a := get("/uploads/a.foo")
	if got := a.Header().Get("Content-Type"); got != "application/x-foo" {
		t.Errorf("uploads AddType = %q, want application/x-foo", got)
	}
	if got := a.Header().Get("Cache-Control"); got != "max-age=86400" {
		t.Errorf("uploads ExpiresDefault Cache-Control = %q, want max-age=86400", got)
	}
	if body := strings.TrimSpace(get("/uploads/").Body.String()); body != "SUBDIR-INDEX" {
		t.Errorf("uploads/ body = %.40q, want the DirectoryIndex file", body)
	}
	if got := get("/quiet/x.txt").Header().Get("Cache-Control"); got != "" {
		t.Errorf("quiet/ Cache-Control = %q, want none (ExpiresActive Off)", got)
	}

	// Only a sub-directory has a file: there is no root .htaccess at all.
	only := t.TempDir()
	writeTree(t, only, map[string]string{
		"uploads/a.foo":     "foo",
		"uploads/.htaccess": "AddType application/x-foo .foo\n",
	})
	if got := htaccessLevelServer(t, "o.test", only)("/uploads/a.foo").Header().Get("Content-Type"); got != "application/x-foo" {
		t.Errorf("sub-directory-only AddType = %q, want application/x-foo", got)
	}
}

// F9403: <Files>/<FilesMatch> are judged against the file served, so a directory
// URL answered by index.html meets "\.html$" and not a section for its own name.
func TestHtaccessFilesMatchUsesServedFile(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"index.html":      "home",
		"docs/index.html": "docs",
		".htaccess":       "<FilesMatch \"\\.html$\">\nHeader set X-Html yes\n</FilesMatch>\n<Files docs>\nHeader set X-Dirname yes\n</Files>\n",
	})
	get := htaccessLevelServer(t, "f.test", dir)
	if get("/index.html").Header().Get("X-Html") != "yes" {
		t.Fatal("control: FilesMatch on /index.html")
	}
	if get("/").Header().Get("X-Html") != "yes" || get("/docs/").Header().Get("X-Html") != "yes" {
		t.Error("a directory URL served from index.html must meet <FilesMatch \"\\.html$\">")
	}
	if got := get("/docs/").Header().Get("X-Dirname"); got != "" {
		t.Errorf("/docs/ matched <Files docs> (%q); the file served is index.html", got)
	}
}
