package static

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/router"
)

// F6900 added a post-open containment check; a doc root that is itself a
// symlink (or sits under one, e.g. /var/www -> /srv/www) must keep serving,
// for plain files and for pre-compressed variants.
func TestServeFromSymlinkedDocRoot(t *testing.T) {
	tmp := t.TempDir()
	real := filepath.Join(tmp, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "a.txt"), []byte("INSIDE-A"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "app.js"), []byte("console.log(1)"), 0o644); err != nil {
		t.Fatal(err)
	}
	gz := filepath.Join(real, "app.js.gz")
	if err := os.WriteFile(gz, []byte("GZIPPED"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The variant must not look older than its source.
	os.Chtimes(gz, mustStat(t, filepath.Join(real, "app.js")).ModTime().Add(1e9), mustStat(t, filepath.Join(real, "app.js")).ModTime().Add(1e9))
	link := filepath.Join(tmp, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	domain := &config.Domain{Host: "example.test", Type: "static", Root: link}
	h := New()
	get := func(uri string, hdr ...string) (int, string, string) {
		t.Helper()
		r := httptest.NewRequest("GET", "http://example.test"+uri, nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		rec := httptest.NewRecorder()
		ctx := &router.RequestContext{Request: r, Response: router.NewResponseWriter(rec)}
		if !ResolveRequest(ctx, domain) {
			return 404, "", ""
		}
		h.Serve(ctx)
		return rec.Code, rec.Body.String(), rec.Header().Get("Content-Encoding")
	}

	if c, b, _ := get("/a.txt"); c != 200 || b != "INSIDE-A" {
		t.Errorf("plain file under a symlinked root: %d %q", c, b)
	}
	if c, b, enc := get("/app.js", "Accept-Encoding", "gzip"); c != 200 || b != "GZIPPED" || enc != "gzip" {
		t.Errorf("pre-compressed variant under a symlinked root: %d %q %q", c, b, enc)
	}
}

func mustStat(t *testing.T, p string) os.FileInfo {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}
