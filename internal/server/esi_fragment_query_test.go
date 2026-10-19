package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

func esiQueryServer(t *testing.T, dir string) (*Server, *http.Request) {
	t.Helper()
	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{{Host: "esi.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"},
			Cache: config.DomainCache{Enabled: true, TTL: 60, ESI: true}}},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	parent := httptest.NewRequest(http.MethodGet, "/page.html", nil)
	parent.RemoteAddr = "192.0.2.5:1"
	parent.Header.Set("User-Agent", "uwas-test")
	return s, parent
}

// F21100: an ESI src with a query string was written back over URL.Path whole,
// so the sub-request looked for a file literally named "frag.html?id=1" and the
// fragment 404ed; the .htaccess guard of the fragment cache looked at the same
// wrong path.
func TestFetchFragmentSrcWithQueryResolvesThePath(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "frag.html"), []byte("FRAG"), 0o644)
	s, parent := esiQueryServer(t, dir)

	for _, src := range []string{"/frag.html", "/frag.html?id=1", "/frag.html?a=1&b=2", "/frag.html?", "/frag.html#top"} {
		body, status, _, err := s.FetchFragment("esi.test", src, parent)
		if err != nil || status != 200 || string(body) != "FRAG" {
			t.Errorf("FetchFragment(%q) = status %d body %q err %v, want 200 FRAG", src, status, body, err)
		}
	}
	// A missing file is still a 404, with or without a query.
	for _, src := range []string{"/nope.html", "/nope.html?id=1"} {
		if _, status, _, err := s.FetchFragment("esi.test", src, parent); err != nil || status != 404 {
			t.Errorf("FetchFragment(%q) status %d err %v, want 404", src, status, err)
		}
	}
}

func TestFragmentURLPath(t *testing.T) {
	for in, want := range map[string]string{
		"/a":       "/a",
		"/a?x=1":   "/a",
		"/a?":      "/a",
		"/a#f":     "/a",
		"/a?x=1#f": "/a",
		"/a%20b?x": "/a%20b",
		"":         "",
	} {
		if got := fragmentURLPath(in); got != want {
			t.Errorf("fragmentURLPath(%q) = %q, want %q", in, got, want)
		}
	}
}
