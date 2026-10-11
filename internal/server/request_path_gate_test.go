package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F14400/F14401: a URL path is answered 414 beyond maxRequestPath before any
// per-request pass (the .htaccess directory walk, location and cache-rule
// regexes) runs over it; real paths and long query strings are unaffected.
func TestRequestPathGate(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "page.txt"), []byte("PAGE"), 0o644)
	s := newDeepPathServer(t, dir)
	get := func(target string) int {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Host = "d.test"
		req.RemoteAddr = "198.51.100.1:1"
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := get("/page.txt"); c != http.StatusOK {
		t.Fatalf("control: /page.txt = %d, want 200", c)
	}
	if c := get("/" + strings.Repeat("a", maxRequestPath-1)); c != http.StatusNotFound {
		t.Errorf("path of %d bytes = %d, want 404 (served normally)", maxRequestPath, c)
	}
	if c := get("/" + strings.Repeat("a", maxRequestPath)); c != http.StatusRequestURITooLong {
		t.Errorf("path of %d bytes = %d, want 414", maxRequestPath+1, c)
	}
	if c := get("/page.txt?q=" + strings.Repeat("b", 20000)); c != http.StatusOK {
		t.Errorf("long query string = %d, want 200: only the path is limited", c)
	}
}
