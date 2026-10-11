package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// locRootServer builds a static domain "a.test" with a main root and a /docs/
// location root holding the same files.
func locRootServer(t *testing.T, extra string) *Server {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "site")
	docs := filepath.Join(dir, "docs")
	for _, d := range []string{root, docs} {
		os.MkdirAll(filepath.Join(d, "sub"), 0o755)
		os.MkdirAll(filepath.Join(d, ".well-known"), 0o755)
		os.WriteFile(filepath.Join(d, "pic.png"), []byte("PNG"), 0o644)
		os.WriteFile(filepath.Join(d, ".secret"), []byte("S"), 0o644)
		os.WriteFile(filepath.Join(d, "sub", "a.txt"), []byte("A"), 0o644)
		os.WriteFile(filepath.Join(d, ".well-known", "ok.txt"), []byte("WK"), 0o644)
	}
	os.WriteFile(filepath.Join(root, "index.html"), []byte("ok"), 0o644)
	os.WriteFile(filepath.Join(docs, "index.html"), []byte("DOCSINDEX"), 0o644)
	y := fmt.Sprintf(`global:
  worker_count: "1"
  log_level: error
  log_format: text
domains:
  - host: a.test
    type: static
    root: %s
    ssl: {mode: "off"}
%s
    locations:
      - match: /docs/
        root: %s
`, root, extra, docs)
	p := filepath.Join(dir, "uwas.yaml")
	os.WriteFile(p, []byte(y), 0o644)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel() })
	s.SetConfigPath(p)
	s.handler = s.buildMiddlewareChain()
	return s
}

func locRootGet(s *Server, path, ref string) (int, string) {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "a.test"
	req.RemoteAddr = "192.0.2.5:1"
	req.Header.Set("User-Agent", "uwas-test")
	if ref != "" {
		req.Header.Set("Referer", ref)
	}
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// F3600: a location root answers the request before the hotlink check, so its
// images could be embedded from any site.
func TestLocationRootHonoursHotlinkProtection(t *testing.T) {
	s := locRootServer(t, "    security:\n      hotlink_protection: {enabled: true, allowed_referers: [\"a.test\"]}")
	const evil = "https://evil.example/"
	if c, _ := locRootGet(s, "/pic.png", evil); c != http.StatusForbidden {
		t.Fatalf("control: main root with foreign referer = %d, want 403", c)
	}
	if c, _ := locRootGet(s, "/docs/pic.png", "https://a.test/page"); c != http.StatusOK {
		t.Fatalf("same-site referer on location root = %d, want 200", c)
	}
	if c, _ := locRootGet(s, "/docs/pic.png", ""); c != http.StatusOK {
		t.Fatalf("no referer on location root = %d, want 200", c)
	}
	if c, _ := locRootGet(s, "/docs/pic.png", evil); c != http.StatusForbidden {
		t.Errorf("foreign referer on location root = %d, want 403", c)
	}
}

// F3601: the domain's static handler refuses any dotfile segment; the location
// root served them through http.ServeFile.
func TestLocationRootRefusesDotfiles(t *testing.T) {
	s := locRootServer(t, "")
	if c, _ := locRootGet(s, "/.secret", ""); c == http.StatusOK {
		t.Fatalf("control: main root /.secret = %d", c)
	}
	if c, b := locRootGet(s, "/docs/.well-known/ok.txt", ""); c != http.StatusOK || b != "WK" {
		t.Fatalf(".well-known on location root = %d %q, want 200 WK", c, b)
	}
	for _, p := range []string{"/docs/.secret", "/docs/%2esecret", "/docs/sub/../.secret", "/docs/.hidden/x"} {
		if c, _ := locRootGet(s, p, ""); c == http.StatusOK {
			t.Errorf("%s = %d, want refused", p, c)
		}
	}
}

// F3602: a location root rendered directory listings even with
// directory_listing off; the domain root answers 404 for the same request.
func TestLocationRootDirectoryListingFollowsDomainSetting(t *testing.T) {
	s := locRootServer(t, "")
	if c, _ := locRootGet(s, "/sub/", ""); c == http.StatusOK {
		t.Fatalf("control: main root /sub/ = %d", c)
	}
	if c, b := locRootGet(s, "/docs/", ""); c != http.StatusOK || b != "DOCSINDEX" {
		t.Fatalf("index.html on location root = %d %q, want 200 DOCSINDEX", c, b)
	}
	for _, p := range []string{"/docs/sub/", "/docs/sub"} {
		c, b := locRootGet(s, p, "")
		if c == http.StatusOK && strings.Contains(b, "a.txt") {
			t.Errorf("%s listed a directory with directory_listing off: %d", p, c)
		}
	}

	s = locRootServer(t, "    directory_listing: true")
	if c, b := locRootGet(s, "/docs/sub/", ""); c != http.StatusOK || !strings.Contains(b, "a.txt") {
		t.Errorf("directory_listing on: /docs/sub/ = %d, want 200 listing", c)
	}
}
