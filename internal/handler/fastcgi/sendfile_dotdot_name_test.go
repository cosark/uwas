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

// The traversal guard rejected any path containing the substring "..", so a
// download whose file name merely contains two dots ("report..pdf", "v1..2")
// was refused and the response fell through to PHP's own (empty) body. Only a
// ".." path element is traversal (F20201).
func TestSendfileAllowsDotDotInsideFileName(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "report.pdf"), []byte("PLAIN"), 0o644)
	os.WriteFile(filepath.Join(root, "report..pdf"), []byte("DOTDOT"), 0o644)
	os.WriteFile(filepath.Join(root, "secret.txt"), []byte("SECRET"), 0o644)

	h := New(logger.New("error", "text"))
	serve := func(header, path string) (bool, string) {
		rec := httptest.NewRecorder()
		ctx := &router.RequestContext{
			Request:  httptest.NewRequest("GET", "http://sf.test/x.php", nil),
			Response: router.NewResponseWriter(rec),
		}
		domain := &config.Domain{Host: "sf.test", Root: root}
		ok := h.tryServeFile(ctx, domain, http.Header{header: []string{path}})
		return ok, rec.Body.String()
	}

	failed := false
	for _, c := range []struct {
		name, header, path, body string
		served                   bool
	}{
		{"control plain name", "X-Sendfile", filepath.Join(root, "report.pdf"), "PLAIN", true},
		{"control accel plain", "X-Accel-Redirect", "/report.pdf", "PLAIN", true},
		{"control traversal element", "X-Sendfile", root + "/sub/../secret.txt", "SECRET", true},
		{"control relative traversal", "X-Sendfile", "../secret.txt", "", false},
		{"dotdot inside name sendfile", "X-Sendfile", filepath.Join(root, "report..pdf"), "DOTDOT", true},
		{"dotdot inside name accel", "X-Accel-Redirect", "/report..pdf", "DOTDOT", true},
	} {
		ok, body := serve(c.header, c.path)
		t.Logf("%s: EXPECTED served=%v body=%q ACTUAL served=%v body=%q", c.name, c.served, c.body, ok, body)
		if ok != c.served || body != c.body {
			failed = true
			t.Errorf("%s: served=%v body=%q, want served=%v body=%q", c.name, ok, body, c.served, c.body)
		}
	}
	if failed {
		t.Log("PROBLEM CONFIRMED")
	} else {
		t.Log("PROBLEM NOT REPRODUCED")
	}
}
