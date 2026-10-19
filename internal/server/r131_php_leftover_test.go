package server

import (
	"net"
	"net/http"
	"net/http/fcgi"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

// F18600: docs/SPECIFICATION.md §16.3 says access to ".php.bak", ".php.old",
// ".php~" and ".phps" files is blocked. They are not scripts to FastCGI (only a
// name ending in ".php" is), so the static handler served them as downloads:
// the source of wp-config.php.bak and friends went to anyone who asked.
func TestPHPSourceLeftoversAreNotServed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "site")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	const src = "<?php $db_password = 'hunter2'; ?>"
	files := []string{
		"wp-config.php.bak", "a.php~", "a.php.old", "a.phps", "A.PHP.BAK", "b.php.orig", "c.php.save", "d.php.swp",
		"ok.txt", "db.sql", "notes.txt.bak", "b.php.txt", "page.html", "report.old", "x.phpx", "a.php",
	}
	for _, n := range files {
		if err := os.WriteFile(filepath.Join(root, n), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var hits atomic.Int32
	go fcgi.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("FPM-OUTPUT"))
	}))
	for _, typ := range []string{"php", "static"} {
		s := newDispatchTestServer(t, []config.Domain{{Host: "s.test", Type: typ, Root: root,
			SSL: config.SSLConfig{Mode: "off"}, PHP: config.PHPConfig{FPMAddress: ln.Addr().String()}}})
		get := func(p string) *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", p, nil)
			req.Host = "s.test"
			req.Header.Set("User-Agent", "uwas-test")
			s.handleRequest(rec, req)
			return rec
		}
		for _, n := range []string{"wp-config.php.bak", "a.php~", "a.php.old", "a.phps", "A.PHP.BAK", "b.php.orig", "c.php.save", "d.php.swp", "a.php%7E"} {
			rec := get("/" + n)
			if rec.Code == 200 || strings.Contains(rec.Body.String(), "hunter2") {
				t.Errorf("%s domain: /%s -> %d, source leaked=%v", typ, n, rec.Code, strings.Contains(rec.Body.String(), "hunter2"))
			}
		}
		// Controls: ordinary files keep being served.
		for _, n := range []string{"ok.txt", "db.sql", "notes.txt.bak", "b.php.txt", "page.html", "report.old", "x.phpx"} {
			if rec := get("/" + n); rec.Code != 200 {
				t.Errorf("%s domain: control /%s -> %d, want 200", typ, n, rec.Code)
			}
		}
	}
	// A location root is served by its own code path, not the static handler.
	sloc := newDispatchTestServer(t, []config.Domain{{Host: "s.test", Type: "static", Root: root,
		SSL:       config.SSLConfig{Mode: "off"},
		Locations: []config.LocationConfig{{Match: "/loc/", Root: root, StripPrefix: true}}}})
	for n, want := range map[string]bool{"wp-config.php.bak": false, "a.php~": false, "ok.txt": true} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/loc/"+n, nil)
		req.Host = "s.test"
		sloc.handleRequest(rec, req)
		if (rec.Code == 200) != want || (!want && strings.Contains(rec.Body.String(), "hunter2")) {
			t.Errorf("location root: /loc/%s -> %d (served=%v want %v)", n, rec.Code, rec.Code == 200, want)
		}
	}
	// The script itself still runs.
	s := newDispatchTestServer(t, []config.Domain{{Host: "s.test", Type: "php", Root: root,
		SSL: config.SSLConfig{Mode: "off"}, PHP: config.PHPConfig{FPMAddress: ln.Addr().String()}}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/a.php", nil)
	req.Host = "s.test"
	s.handleRequest(rec, req)
	if hits.Load() == 0 || !strings.Contains(rec.Body.String(), "FPM-OUTPUT") {
		t.Errorf("/a.php did not run through FastCGI: %d %q", rec.Code, rec.Body.String())
	}
}
