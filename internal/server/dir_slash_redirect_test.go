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

// F10200: a directory requested without its trailing slash used to be served
// in place, so the index page's relative URLs resolved against the parent
// directory. Apache and nginx redirect to "/dir/".
func TestDirectoryWithoutSlashRedirects(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"docs", "evil.com", "priv"} {
		os.MkdirAll(filepath.Join(dir, d), 0o755)
		os.WriteFile(filepath.Join(dir, d, "index.html"), []byte(d+"-INDEX"), 0o644)
	}
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("ROOT-INDEX"), 0o644)
	os.WriteFile(filepath.Join(dir, "a.css"), []byte("body{}"), 0o644)
	os.WriteFile(filepath.Join(dir, "priv", ".htaccess"), []byte("Require all denied\n"), 0o644)

	spa := t.TempDir()
	os.WriteFile(filepath.Join(spa, "index.html"), []byte("SPA-SHELL"), 0o644)
	os.MkdirAll(filepath.Join(spa, "docs"), 0o755)
	os.WriteFile(filepath.Join(spa, "docs", "index.html"), []byte("SPA-DOCS"), 0o644)

	rw := t.TempDir()
	os.MkdirAll(filepath.Join(rw, "real"), 0o755)
	os.WriteFile(filepath.Join(rw, "real", "index.html"), []byte("REAL-INDEX"), 0o644)
	os.WriteFile(filepath.Join(rw, ".htaccess"), []byte("RewriteEngine On\nRewriteRule ^alias$ /real [L]\n"), 0o644)

	cfg := &config.Config{Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{
			{Host: "d.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"}, Htaccess: config.HtaccessConfig{Mode: "import"}},
			{Host: "spa.test", Type: "static", Root: spa, SPAMode: true, SSL: config.SSLConfig{Mode: "off"}},
			{Host: "rw.test", Type: "static", Root: rw, SSL: config.SSLConfig{Mode: "off"}, Htaccess: config.HtaccessConfig{Mode: "import"}},
		}}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	do := func(method, host, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Host = host
		req.RemoteAddr = "192.0.2.5:1"
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec
	}

	t.Run("redirects", func(t *testing.T) {
		for _, c := range []struct{ method, host, path, want string }{
			{"GET", "d.test", "/docs", "/docs/"},
			{"HEAD", "d.test", "/docs", "/docs/"},
			{"GET", "d.test", "/docs?x=1&y=2", "/docs/?x=1&y=2"},
			{"GET", "spa.test", "/docs", "/docs/"},
		} {
			r := do(c.method, c.host, c.path)
			if r.Code != http.StatusMovedPermanently || r.Header().Get("Location") != c.want {
				t.Errorf("%s %s%s: %d Location=%q, want 301 %q", c.method, c.host, c.path, r.Code, r.Header().Get("Location"), c.want)
			}
		}
	})
	t.Run("served in place", func(t *testing.T) {
		for _, c := range []struct{ method, host, path, want string }{
			{"GET", "d.test", "/docs/", "docs-INDEX"},
			{"GET", "d.test", "/", "ROOT-INDEX"},
			{"GET", "d.test", "/a.css", "body{}"},
			{"GET", "spa.test", "/some/route", "SPA-SHELL"},
			{"POST", "d.test", "/docs", "docs-INDEX"}, // a 301 would turn the POST into a GET
		} {
			r := do(c.method, c.host, c.path)
			if r.Code != http.StatusOK || r.Body.String() != c.want || r.Header().Get("Location") != "" {
				t.Errorf("%s %s%s: %d %q Location=%q, want 200 %q", c.method, c.host, c.path, r.Code, r.Body.String(), r.Header().Get("Location"), c.want)
			}
		}
	})
	t.Run("never a scheme-relative location", func(t *testing.T) {
		r := do("GET", "d.test", "//evil.com")
		if loc := r.Header().Get("Location"); strings.HasPrefix(loc, "//") || strings.Contains(loc, "://") {
			t.Errorf("Location = %q, want a path on this host", loc)
		}
	})
	t.Run("denied directory does not reveal itself", func(t *testing.T) {
		r := do("GET", "d.test", "/priv")
		if r.Code != http.StatusForbidden || r.Header().Get("Location") != "" {
			t.Errorf("/priv: %d Location=%q, want 403 without redirect", r.Code, r.Header().Get("Location"))
		}
	})
	t.Run("rewritten request keeps its own URL", func(t *testing.T) {
		r := do("GET", "rw.test", "/alias")
		if r.Header().Get("Location") != "" || r.Body.String() != "REAL-INDEX" {
			t.Errorf("/alias: %d %q Location=%q, want the rewritten directory served without exposing /real/", r.Code, r.Body.String(), r.Header().Get("Location"))
		}
	})
}
