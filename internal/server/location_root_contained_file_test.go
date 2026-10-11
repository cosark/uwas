package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/router"
)

// F7220: a location root used to hand the validated path to http.ServeFile,
// which opens it by name again; a file swapped for a symlink in between was
// served from outside the root. serveContainedFile serves the handle it opened
// after confirming it is still inside the root.
func TestLocationRootServesOnlyContainedHandles(t *testing.T) {
	tmp := t.TempDir()
	site := filepath.Join(tmp, "site")
	docs := filepath.Join(tmp, "docs")
	outside := filepath.Join(tmp, "outside")
	for _, d := range []string{site, docs, outside} {
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
	write(filepath.Join(site, "index.html"), "ok")
	write(filepath.Join(docs, "a.txt"), "INSIDE-DOCS")
	write(filepath.Join(docs, "page.css"), "body{}")
	write(filepath.Join(docs, "index.html"), "DOCS-INDEX")
	write(filepath.Join(outside, "secret.txt"), "SECRET-OUTSIDE")
	os.Symlink(filepath.Join(docs, "a.txt"), filepath.Join(docs, "inner.txt"))
	os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(docs, "out.txt"))
	docsLink := filepath.Join(tmp, "docslink")
	os.Symlink(docs, docsLink)

	s := newDispatchTestServer(t, []config.Domain{{
		Host: "loc.test", Type: "static", Root: site, SSL: config.SSLConfig{Mode: "off"},
		Locations: []config.LocationConfig{
			{Match: "/docs/", Root: docs},
			{Match: "/link/", Root: docsLink},
		},
	}})
	get := func(path string, hdr ...string) (int, string, http.Header) {
		t.Helper()
		req := httptest.NewRequest("GET", path, nil)
		req.Host = "loc.test"
		req.RemoteAddr = "192.0.2.5:1"
		req.Header.Set("User-Agent", "uwas-test")
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		rec := httptest.NewRecorder()
		s.handleRequest(rec, req)
		return rec.Code, rec.Body.String(), rec.Header()
	}

	if c, b, h := get("/docs/a.txt"); c != 200 || b != "INSIDE-DOCS" || h.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Errorf("plain file: %d %q %q", c, b, h.Get("Content-Type"))
	}
	if c, _, h := get("/docs/page.css"); c != 200 || h.Get("Content-Type") != "text/css; charset=utf-8" {
		t.Errorf("css file: %d %q", c, h.Get("Content-Type"))
	}
	if c, b, _ := get("/docs/a.txt", "Range", "bytes=0-5"); c != http.StatusPartialContent || b != "INSIDE" {
		t.Errorf("range request: %d %q, want 206 INSIDE", c, b)
	}
	if c, b, _ := get("/docs/inner.txt"); c != 200 || b != "INSIDE-DOCS" {
		t.Errorf("symlink inside the root: %d %q", c, b)
	}
	if c, b, _ := get("/link/a.txt"); c != 200 || b != "INSIDE-DOCS" {
		t.Errorf("symlinked location root: %d %q", c, b)
	}
	if c, b, _ := get("/docs/"); c != 200 || b != "DOCS-INDEX" {
		t.Errorf("directory index via ServeFile: %d %q", c, b)
	}
	if c, b, _ := get("/docs/out.txt"); b == "SECRET-OUTSIDE" || c == 200 {
		t.Errorf("cold outside symlink served: %d %q", c, b)
	}

	// The post-open confirmation itself: a path that now resolves outside the
	// root is refused even though the caller already validated it earlier.
	req := httptest.NewRequest("GET", "/docs/out.txt", nil)
	rec := httptest.NewRecorder()
	ctx := &router.RequestContext{Request: req, Response: router.NewResponseWriter(rec)}
	if !s.serveContainedFile(ctx, req, &s.config.Domains[0], docs, filepath.Join(docs, "out.txt")) {
		t.Error("serveContainedFile left an outside file to http.ServeFile")
	}
	if rec.Code != http.StatusNotFound || rec.Body.String() == "SECRET-OUTSIDE" {
		t.Errorf("outside handle: %d %q, want 404 without the secret", rec.Code, rec.Body.String())
	}
}
