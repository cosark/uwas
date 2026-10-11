package server

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

// F7230: the directory listing reads the directory through a handle that was
// confirmed to lie inside the root, instead of validating the path and reading
// it by name afterwards. Listings of ordinary directories, in-root symlinked
// directories and symlinked doc roots must keep working; a directory that
// resolves outside the root must not be listed.
func TestDirectoryListingReadsConfirmedHandle(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "root")
	outside := filepath.Join(tmp, "outside")
	for _, d := range []string{filepath.Join(root, "pub"), filepath.Join(root, "real"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p string) {
		t.Helper()
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "pub", "inside-file.txt"))
	write(filepath.Join(root, "real", "real-file.txt"))
	write(filepath.Join(outside, "secret-name.txt"))
	os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "inner"))
	os.Symlink(outside, filepath.Join(root, "out"))
	rootLink := filepath.Join(tmp, "rootlink")
	os.Symlink(root, rootLink)

	s := newDispatchTestServer(t, []config.Domain{
		{Host: "ls.test", Type: "static", Root: root, DirectoryListing: true, SSL: config.SSLConfig{Mode: "off"}},
		{Host: "link.test", Type: "static", Root: rootLink, DirectoryListing: true, SSL: config.SSLConfig{Mode: "off"}},
	})
	get := func(host, path string) (int, string) {
		t.Helper()
		req := httptest.NewRequest("GET", path, nil)
		req.Host = host
		req.RemoteAddr = "192.0.2.5:1"
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handleRequest(rec, req)
		return rec.Code, rec.Body.String()
	}

	if c, b := get("ls.test", "/pub/"); c != 200 || !strings.Contains(b, "inside-file.txt") {
		t.Errorf("plain directory: %d", c)
	}
	if c, b := get("ls.test", "/inner/"); c != 200 || !strings.Contains(b, "real-file.txt") {
		t.Errorf("symlinked directory inside the root: %d", c)
	}
	if c, b := get("link.test", "/pub/"); c != 200 || !strings.Contains(b, "inside-file.txt") {
		t.Errorf("symlinked doc root: %d", c)
	}
	if c, b := get("ls.test", "/out/"); strings.Contains(b, "secret-name.txt") || c == 200 {
		t.Errorf("directory resolving outside the root listed: %d", c)
	}
}
