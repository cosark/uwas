package server

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

// A precompressed sibling (.gz/.br) is served in place of the origin, so a
// symbolic link planted as the sibling must be refused where
// "Options -FollowSymLinks" applies, like any other link.
func TestHtaccessNoFollowSymLinksPrecompressedVariant(t *testing.T) {
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "locked"), 0o755))
	must(os.MkdirAll(filepath.Join(root, "open"), 0o755))
	must(os.WriteFile(filepath.Join(root, "secret.gz"), []byte("SECRETGZ"), 0o644))
	must(os.WriteFile(filepath.Join(root, "locked/.htaccess"), []byte("Options -FollowSymLinks\n"), 0o644))
	for _, d := range []string{"locked", "open"} {
		must(os.WriteFile(filepath.Join(root, d, "a.css"), []byte("body{}"), 0o644))
		must(os.Symlink("../secret.gz", filepath.Join(root, d, "a.css.gz")))
	}
	s := newDispatchTestServer(t, []config.Domain{{Host: "s.test", Type: "static", Root: root,
		SSL: config.SSLConfig{Mode: "off"}}})
	get := func(path string) (int, string) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		req.Host = "s.test"
		req.Header.Set("User-Agent", "uwas-test")
		req.Header.Set("Accept-Encoding", "gzip")
		s.handleRequest(rec, req)
		return rec.Code, rec.Body.String()
	}
	if _, body := get("/open/a.css"); body != "SECRETGZ" {
		t.Logf("control: precompressed link not served in open dir (body %q); test premise weak", body)
	}
	if code, body := get("/locked/a.css"); body == "SECRETGZ" {
		t.Errorf("symlinked .gz variant served under -FollowSymLinks (status %d)", code)
	}
}
