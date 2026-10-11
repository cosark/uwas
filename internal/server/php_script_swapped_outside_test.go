package server

import (
	"net"
	"net/http"
	"net/http/fcgi"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

// F7200: ResolveRequest's containment verdict rests on pathsafe's cached
// resolution, and PHP-FPM follows symlinks when it opens SCRIPT_FILENAME, so a
// script swapped for a symlink to a file outside the root was still executed
// until the cache entry expired. The server re-resolves before the hand-off.
func TestPHPScriptSwappedForOutsideSymlinkIsNotExecuted(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "root")
	outside := filepath.Join(tmp, "outside")
	for _, d := range []string{root, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, body string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "x.php"), "<?php // inside")
	write(filepath.Join(root, "real.php"), "<?php // inside real")
	write(filepath.Join(outside, "evil.php"), "<?php // outside")
	if err := os.Symlink(filepath.Join(root, "real.php"), filepath.Join(root, "inner.php")); err != nil {
		t.Fatal(err)
	}
	// The doc root itself reached through a symlink must keep working.
	rootLink := filepath.Join(tmp, "rootlink")
	if err := os.Symlink(root, rootLink); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ran := make(chan string, 16)
	go fcgi.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		real, _ := filepath.EvalSymlinks(fcgi.ProcessEnv(r)["SCRIPT_FILENAME"])
		ran <- real
		w.Write([]byte("ok"))
	}))

	s := newDispatchTestServer(t, []config.Domain{
		{Host: "swap.test", Type: "php", Root: root, SSL: config.SSLConfig{Mode: "off"},
			PHP: config.PHPConfig{FPMAddress: ln.Addr().String()}},
		{Host: "link.test", Type: "php", Root: rootLink, SSL: config.SSLConfig{Mode: "off"},
			PHP: config.PHPConfig{FPMAddress: ln.Addr().String()}},
	})
	get := func(host, path string) (int, string) {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		req.Host = host
		req.Header.Set("User-Agent", "uwas-test")
		s.handleRequest(rec, req)
		select {
		case real := <-ran:
			return rec.Code, real
		default:
			return rec.Code, ""
		}
	}
	realRoot, _ := filepath.EvalSymlinks(root)

	// Warm the resolution cache with ordinary traffic.
	if code, real := get("swap.test", "/x.php"); code != http.StatusOK || !strings.HasPrefix(real, realRoot) {
		t.Fatalf("warm-up GET /x.php = %d running %q, want 200 inside the root", code, real)
	}
	// Controls: a symlink that stays inside the root and a symlinked doc root
	// still run.
	if code, real := get("swap.test", "/inner.php"); code != http.StatusOK || real != filepath.Join(realRoot, "real.php") {
		t.Errorf("in-root symlink: %d running %q, want 200 running real.php", code, real)
	}
	if code, real := get("link.test", "/x.php"); code != http.StatusOK || real != filepath.Join(realRoot, "x.php") {
		t.Errorf("symlinked doc root: %d running %q, want 200 running x.php", code, real)
	}

	if err := os.Remove(filepath.Join(root, "x.php")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "evil.php"), filepath.Join(root, "x.php")); err != nil {
		t.Fatal(err)
	}
	code, real := get("swap.test", "/x.php")
	if real != "" {
		t.Errorf("swapped script executed %q outside the root (status %d)", real, code)
	}
	if code != http.StatusNotFound {
		t.Errorf("swapped script status = %d, want 404", code)
	}
}
