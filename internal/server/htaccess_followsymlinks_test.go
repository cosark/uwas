package server

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

// F16900: "Options -FollowSymLinks" was parsed (RuleSet.FollowSymlinks) and read
// by nothing, so a symbolic link planted in a directory that asked for the
// opposite was followed and served a file the site refuses to serve directly.
func TestHtaccessNoFollowSymLinksRefusesLinks(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, rel string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	write(".env", "DB_PASSWORD=hunter2")
	write("pub/real.txt", "public")
	write("locked/.htaccess", "Options -FollowSymLinks\n")
	write("locked/plain.txt", "plain")
	write("locked/sub/.htaccess", "Options +FollowSymLinks\n")
	write("locked/deep/inner.txt", "inner")
	write("open/plain.txt", "open")
	link("../.env", "locked/env.txt")
	link("../pub/real.txt", "locked/real.txt")
	link("../pub", "locked/dirlink")
	link("../../pub/real.txt", "locked/sub/lifted.txt")
	link("../.env", "open/env.txt")
	link("../../pub/real.txt", "locked/deep/deeplink.txt")

	s := newDispatchTestServer(t, []config.Domain{{Host: "s.test", Type: "static", Root: root,
		SSL: config.SSLConfig{Mode: "off"}}})
	get := func(path string) (int, string) {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		req.Host = "s.test"
		req.Header.Set("User-Agent", "uwas-test")
		s.handleRequest(rec, req)
		return rec.Code, rec.Body.String()
	}

	for _, c := range []struct {
		path string
		code int
		why  string
	}{
		{"/locked/plain.txt", 200, "a regular file in the directory is served"},
		{"/locked/deep/inner.txt", 200, "a regular file below is served"},
		{"/open/plain.txt", 200, "no directive, no change"},
		{"/open/env.txt", 200, "a link where the directive is absent is followed (Apache default)"},
		{"/locked/env.txt", 403, "a link to a refused file"},
		{"/locked/real.txt", 403, "a link to a public file is still a link"},
		{"/locked/dirlink/real.txt", 403, "a link on the way is a link"},
		{"/locked/deep/deeplink.txt", 403, "the refusal covers the subtree"},
		{"/locked/sub/lifted.txt", 200, "+FollowSymLinks in a subdirectory lifts the parent's refusal"},
	} {
		if code, body := get(c.path); code != c.code {
			t.Errorf("%s: status %d, want %d (%s); body %q", c.path, code, c.code, c.why, body)
		}
	}
	if _, body := get("/locked/env.txt"); body == "DB_PASSWORD=hunter2" {
		t.Error("the secret behind the link was served")
	}
}
