package static

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/router"
)

// F6900: pathsafe caches the resolution behind ResolveRequest's containment
// verdict for a few seconds, so a served file (or one of its directories)
// swapped for a symlink to somewhere outside the root kept being served from
// outside. Serve now re-verifies the file it opened.
func TestServeRejectsFileSwappedForOutsideSymlink(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "root")
	outside := filepath.Join(tmp, "outside")
	for _, d := range []string{filepath.Join(root, "sub"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(outside, "secret.txt")
	write := func(p, body string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(secret, "SECRET-OUTSIDE")
	write(filepath.Join(root, "a.txt"), "INSIDE-A")
	write(filepath.Join(root, "keep.txt"), "INSIDE-KEEP")
	write(filepath.Join(root, "inner.txt"), "INSIDE-INNER")
	write(filepath.Join(root, "sub", "d.txt"), "INSIDE-D")
	write(filepath.Join(outside, "d.txt"), "SECRET-D-OUTSIDE")
	if err := os.Symlink(filepath.Join(root, "inner.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}

	domain := &config.Domain{Host: "example.test", Type: "static", Root: root}
	h := New()
	get := func(uri string) (int, string) {
		t.Helper()
		r := httptest.NewRequest("GET", "http://example.test"+uri, nil)
		rec := httptest.NewRecorder()
		ctx := &router.RequestContext{Request: r, Response: router.NewResponseWriter(rec)}
		if !ResolveRequest(ctx, domain) {
			return http.StatusNotFound, ""
		}
		h.Serve(ctx)
		return rec.Code, rec.Body.String()
	}

	// Warm the resolution cache for every path, as ordinary traffic does.
	for uri, want := range map[string]string{
		"/a.txt": "INSIDE-A", "/keep.txt": "INSIDE-KEEP",
		"/link.txt": "INSIDE-INNER", "/sub/d.txt": "INSIDE-D",
	} {
		if code, body := get(uri); code != 200 || body != want {
			t.Fatalf("warm %s = %d %q, want 200 %q", uri, code, body, want)
		}
	}

	// The file becomes a symlink to a file outside the root.
	os.Remove(filepath.Join(root, "a.txt"))
	if err := os.Symlink(secret, filepath.Join(root, "a.txt")); err != nil {
		t.Fatal(err)
	}
	// A directory on the way becomes a symlink to an outside directory.
	os.RemoveAll(filepath.Join(root, "sub"))
	if err := os.Symlink(outside, filepath.Join(root, "sub")); err != nil {
		t.Fatal(err)
	}

	for _, uri := range []string{"/a.txt", "/sub/d.txt"} {
		code, body := get(uri)
		if code == 200 || body == "SECRET-OUTSIDE" || body == "SECRET-D-OUTSIDE" {
			t.Errorf("%s served from outside the root: %d %q", uri, code, body)
		}
	}

	// Controls: untouched files and an in-root symlink keep working.
	for uri, want := range map[string]string{"/keep.txt": "INSIDE-KEEP", "/link.txt": "INSIDE-INNER"} {
		if code, body := get(uri); code != 200 || body != want {
			t.Errorf("control %s = %d %q, want 200 %q", uri, code, body, want)
		}
	}
}
