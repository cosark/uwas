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

// F11201: the RewriteRule and Redirect directives of a sub-directory's
// .htaccess are applied (only the document root's were), most importantly the
// upload protection "RewriteRule \.php$ - [F]".
func TestHtaccessSubdirectoryRewriteAndRedirect(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
	}
	write("uploads/.htaccess", "RewriteEngine On\nRewriteRule \\.php$ - [F]\nRewriteRule ^old\\.txt$ new.txt [L]\nRewriteRule ^gone\\.txt$ - [G]\nRedirect 301 /uploads/moved.txt /uploads/new.txt\n")
	write("uploads/shell.php", "PHP-SOURCE")
	write("uploads/deep/x.php", "PHP-DEEP")
	write("uploads/new.txt", "NEW")
	write("uploads/pic.txt", "PIC")
	write("other/shell.php", "OTHER-PHP")
	write("shell.php", "ROOT-PHP")

	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{{
			Host: "sub.test", Type: "static", Root: root, SSL: config.SSLConfig{Mode: "off"},
			Htaccess: config.HtaccessConfig{Mode: "import"},
		}},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()

	get := func(path string) (int, string, string) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "sub.test"
		req.RemoteAddr = "198.51.100.7:1"
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String(), rec.Header().Get("Location")
	}
	cases := []struct {
		path string
		code int
		body string // checked only when non-empty
		loc  string
	}{
		{path: "/uploads/shell.php", code: 403},  // sub-directory [F]
		{path: "/uploads/deep/x.php", code: 403}, // below the directory with the file
		{path: "/uploads//shell.php", code: 403}, // canonical path, as the root rules (F2530)
		{path: "/uploads/gone.txt", code: 410},   // sub-directory [G]
		{path: "/uploads/moved.txt", code: 301, loc: "/uploads/new.txt"},
		{path: "/uploads/old.txt", code: 200, body: "NEW"},       // relative substitution gets the directory prefix
		{path: "/uploads/pic.txt", code: 200, body: "PIC"},       // control: unrelated file in the directory
		{path: "/other/shell.php", code: 200, body: "OTHER-PHP"}, // control: another directory
		{path: "/shell.php", code: 200, body: "ROOT-PHP"},        // control: the root
	}
	for _, c := range cases {
		code, body, loc := get(c.path)
		if code != c.code || (c.body != "" && body != c.body) || (c.loc != "" && loc != c.loc) {
			if len(body) > 40 {
				body = body[:40] + "..."
			}
			t.Errorf("GET %s = %d %q Location=%q; want %d %q %q", c.path, code, body, loc, c.code, c.body, c.loc)
		}
	}
}
