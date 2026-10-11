package fastcgi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
	"github.com/uwaserver/uwas/internal/router"
)

// F7210: X-Sendfile now confirms the file it opened is still inside the
// allowed root; ordinary files, symlinks that stay inside and symlinked doc
// roots must keep being served.
func TestSendfileServesOnlyContainedFiles(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "root")
	outside := filepath.Join(tmp, "outside")
	for _, d := range []string{root, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(root, "file.txt"), []byte("INSIDE"), 0o644)
	os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("SECRET-OUTSIDE"), 0o644)
	os.Symlink(filepath.Join(root, "file.txt"), filepath.Join(root, "inner.txt"))
	os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "out.txt"))
	rootLink := filepath.Join(tmp, "rootlink")
	os.Symlink(root, rootLink)

	h := New(logger.New("error", "text"))
	serve := func(domRoot, header, path string) (bool, string) {
		rec := httptest.NewRecorder()
		ctx := &router.RequestContext{
			Request:  httptest.NewRequest("GET", "http://sf.test/x.php", nil),
			Response: router.NewResponseWriter(rec),
		}
		domain := &config.Domain{Host: "sf.test", Root: domRoot}
		ok := h.tryServeFile(ctx, domain, http.Header{header: []string{path}})
		return ok, rec.Body.String()
	}

	for _, c := range []struct {
		name, root, header, path, body string
		served                         bool
	}{
		{"plain file", root, "X-Sendfile", filepath.Join(root, "file.txt"), "INSIDE", true},
		{"symlink inside the root", root, "X-Sendfile", filepath.Join(root, "inner.txt"), "INSIDE", true},
		{"symlinked doc root", rootLink, "X-Sendfile", filepath.Join(rootLink, "file.txt"), "INSIDE", true},
		{"accel redirect", root, "X-Accel-Redirect", "/file.txt", "INSIDE", true},
		{"symlink to outside", root, "X-Sendfile", filepath.Join(root, "out.txt"), "", false},
	} {
		ok, body := serve(c.root, c.header, c.path)
		if ok != c.served || body != c.body {
			t.Errorf("%s: served=%v body=%q, want served=%v body=%q", c.name, ok, body, c.served, c.body)
		}
	}
}
