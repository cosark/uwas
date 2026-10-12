package server

import (
	"net"
	"net/http"
	"net/http/fcgi"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F17400: the file-serving branches of "Options -FollowSymLinks" (F16900/F16902)
// exercised through the real handleRequest, each against a link that points
// at a file the site refuses to serve directly (a dot directory in the root;
// links leaving the root are refused by the containment check regardless). With the directive the secret must
// never reach the body; the same request without it is the control (the link
// is followed, which proves the request really reaches the branch).
const matrixSecret = "TOPSECRET-HIDDEN-IN-DOCROOT"

type matrixSite struct {
	root, outside string
}

func buildMatrixSite(t *testing.T, directive bool) matrixSite {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "site")
	outside := filepath.Join(root, ".private") // inside the root but refused directly (dot directory)
	w := func(p, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	l := func(target, p string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	w(filepath.Join(outside, "secret.txt"), matrixSecret)
	w(filepath.Join(outside, "index.html"), matrixSecret)
	w(filepath.Join(outside, "page.html"), matrixSecret)
	ht := "Options +Indexes\n"
	if directive {
		ht += "Options -FollowSymLinks\n"
	}
	w(filepath.Join(root, "locked/.htaccess"), ht)
	w(filepath.Join(root, "locked/plain.txt"), "plain")
	l(filepath.Join(outside, "secret.txt"), filepath.Join(root, "locked/file.txt"))       // (1)
	l(outside, filepath.Join(root, "locked/dirlink"))                                     // (2)
	l(filepath.Join(outside, "index.html"), filepath.Join(root, "locked/idx/index.html")) // (3)
	l(filepath.Join(outside, "page.html"), filepath.Join(root, "locked/err404.html"))     // (12)
	return matrixSite{root: root, outside: outside}
}

func matrixGet(s *Server, path string, hdr map[string]string) (int, string) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", path, nil)
	req.Host = "s.test"
	req.Header.Set("User-Agent", "uwas-test")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	s.handleRequest(rec, req)
	return rec.Code, rec.Body.String()
}

func TestHtaccessNoFollowSymLinksMatrixStatic(t *testing.T) {
	type tc struct {
		name, path string
		hdr        map[string]string
	}
	cases := []tc{
		{"1 final-component link", "/locked/file.txt", nil},
		{"2 intermediate dir link", "/locked/dirlink/secret.txt", nil},
		{"3 directory index is a link", "/locked/idx/", nil},
		{"3b directory index via bare dir", "/locked/idx", nil},
		{"6 rewrite-mapped target", "/r/file", nil},
		{"7 location root", "/loc/file.txt", nil},
		{"7b location root via dir link", "/loc/dirlink/secret.txt", nil},
		{"10 listing through dir link", "/locked/dirlink/", nil},
		{"13 range", "/locked/file.txt", map[string]string{"Range": "bytes=0-5"}},
		{"13b conditional", "/locked/file.txt", map[string]string{"If-Modified-Since": "Mon, 01 Jan 2001 00:00:00 GMT"}},
		{"13c accept-encoding", "/locked/file.txt", map[string]string{"Accept-Encoding": "gzip, br"}},
		{"12 error page symlink", "/locked/missing.txt", nil},
		{"5 path-info on static", "/locked/file.txt/x", nil},
	}
	for _, directive := range []bool{true, false} {
		site := buildMatrixSite(t, directive)
		s := newDispatchTestServer(t, []config.Domain{{Host: "s.test", Type: "static", Root: site.root,
			SSL:        config.SSLConfig{Mode: "off"},
			Rewrites:   []config.RewriteRule{{Match: "^/r/file$", To: "/locked/file.txt", Flags: []string{"L"}}},
			Locations:  []config.LocationConfig{{Match: "/loc/", Root: filepath.Join(site.root, "locked"), StripPrefix: true}},
			ErrorPages: map[int]string{404: "locked/err404.html"},
		}})
		for _, c := range cases {
			code, body := matrixGet(s, c.path, c.hdr)
			leaked := strings.Contains(body, matrixSecret)
			if directive && leaked {
				t.Errorf("%s: %s leaked the secret under -FollowSymLinks (status %d)", c.name, c.path, code)
			}
			if !directive {
				t.Logf("control %-32s status %d leaked=%v", c.name, code, leaked)
			}
		}
	}
}

// (4)(5) a PHP script behind a link must not reach FastCGI under the directive:
// executing it would run code the site refuses to serve (and a hidden script
// the dotfile guard hides), including with PATH_INFO appended.
func TestHtaccessNoFollowSymLinksMatrixPHP(t *testing.T) {
	cases := []struct{ name, path string }{
		{"4 script symlink", "/locked/s.php"},
		{"5 PATH_INFO after a link", "/locked/s.php/extra"},
		{"4b script via dir link", "/locked/dirlink/s.php"},
		{"4c script via dir link with PATH_INFO", "/locked/dirlink/s.php/extra"},
		{"6 rewrite-mapped script", "/r/script"},
	}
	for _, directive := range []bool{true, false} {
		site := buildMatrixSite(t, directive)
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		must(os.WriteFile(filepath.Join(site.outside, "s.php"), []byte("<?php"), 0o644))
		must(os.Symlink(filepath.Join(site.outside, "s.php"), filepath.Join(site.root, "locked/s.php")))

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		must(err)
		t.Cleanup(func() { ln.Close() })
		var hits atomic.Int32
		go fcgi.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.Write([]byte(matrixSecret))
		}))
		s := newDispatchTestServer(t, []config.Domain{{Host: "s.test", Type: "php", Root: site.root,
			SSL:      config.SSLConfig{Mode: "off"},
			PHP:      config.PHPConfig{FPMAddress: ln.Addr().String()},
			Rewrites: []config.RewriteRule{{Match: "^/r/script$", To: "/locked/s.php", Flags: []string{"L"}}},
		}})
		for _, c := range cases {
			before := hits.Load()
			code, body := matrixGet(s, c.path, nil)
			reached := hits.Load() != before
			if directive && (reached || strings.Contains(body, matrixSecret)) {
				t.Errorf("%s: %s reached FastCGI=%v status %d under -FollowSymLinks", c.name, c.path, reached, code)
			}
			if !directive {
				t.Logf("control %-38s status %d reached=%v", c.name, code, reached)
			}
		}
	}
}

func newMatrixCacheServer(t *testing.T, dom config.Domain) *Server {
	t.Helper()
	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text",
			Cache: config.CacheConfig{Enabled: true, MemoryLimit: 8 << 20, DefaultTTL: 300}},
		Domains: []config.Domain{dom},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel() })
	return s
}

func matrixGetHdr(s *Server, path string) (int, string, string) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", path, nil)
	req.Host = "s.test"
	req.Header.Set("User-Agent", "uwas-test")
	s.handleRequest(rec, req)
	return rec.Code, rec.Body.String(), rec.Header().Get("X-Cache")
}

// (9) a response cached while a link was still followed must not be replayed
// once "Options -FollowSymLinks" governs the path.
func TestHtaccessNoFollowSymLinksMatrixCacheHit(t *testing.T) {
	site := buildMatrixSite(t, false)
	s := newMatrixCacheServer(t, config.Domain{Host: "s.test", Type: "static", Root: site.root,
		SSL: config.SSLConfig{Mode: "off"}, Cache: config.DomainCache{Enabled: true, TTL: 300}})
	path := "/locked/file.txt"
	c1, b1, _ := matrixGetHdr(s, path)
	c2, b2, xc := matrixGetHdr(s, path)
	if xc != "HIT" || !strings.Contains(b1, matrixSecret) || !strings.Contains(b2, matrixSecret) {
		t.Fatalf("control premise broken: fill %d, second %d X-Cache=%q", c1, c2, xc)
	}
	if err := os.WriteFile(filepath.Join(site.root, "locked/.htaccess"), []byte("Options -FollowSymLinks\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if code, body, xc := matrixGetHdr(s, path); strings.Contains(body, matrixSecret) {
		t.Errorf("cached response replayed under -FollowSymLinks (status %d, X-Cache=%q)", code, xc)
	}
}

// (8) an ESI include is fetched as an internal request and must obey the same
// refusal: a page may not pull a link-reached file into its own body.
func TestHtaccessNoFollowSymLinksMatrixESI(t *testing.T) {
	for _, directive := range []bool{false, true} {
		site := buildMatrixSite(t, directive)
		if err := os.WriteFile(filepath.Join(site.root, "page.html"),
			[]byte(`<html><body>X<!--esi <esi:include src="/locked/file.txt"/> -->Y</body></html>`), 0o644); err != nil {
			t.Fatal(err)
		}
		s := newMatrixCacheServer(t, config.Domain{Host: "s.test", Type: "static", Root: site.root,
			SSL: config.SSLConfig{Mode: "off"}, Cache: config.DomainCache{Enabled: true, TTL: 300, ESI: true}})
		for i := 0; i < 2; i++ { // miss (fill) then hit (assemble)
			code, body, xc := matrixGetHdr(s, "/page.html")
			leaked := strings.Contains(body, matrixSecret)
			if !directive {
				t.Logf("control pass %d: status %d X-Cache=%q leaked=%v body=%q", i, code, xc, leaked, body)
				continue
			}
			if leaked {
				t.Errorf("pass %d: ESI include pulled a link-reached file under -FollowSymLinks (status %d)", i, code)
			}
		}
	}
}

// (8b) a fragment cached while the link was still followed must not be
// replayed into a page once "Options -FollowSymLinks" governs its path.
func TestHtaccessNoFollowSymLinksMatrixESIFragmentCache(t *testing.T) {
	site := buildMatrixSite(t, false)
	if err := os.WriteFile(filepath.Join(site.root, "page.html"),
		[]byte(`<html><body>X<!--esi <esi:include src="/locked/file.txt"/> -->Y</body></html>`), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newMatrixCacheServer(t, config.Domain{Host: "s.test", Type: "static", Root: site.root,
		SSL: config.SSLConfig{Mode: "off"}, Cache: config.DomainCache{Enabled: true, TTL: 300, ESI: true}})
	matrixGetHdr(s, "/page.html")
	if _, body, _ := matrixGetHdr(s, "/page.html"); !strings.Contains(body, matrixSecret) {
		t.Fatalf("control premise broken: fragment not assembled (%q)", body)
	}
	if err := os.WriteFile(filepath.Join(site.root, "locked/.htaccess"), []byte("Options -FollowSymLinks\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	for i := 0; i < 2; i++ {
		if code, body, _ := matrixGetHdr(s, "/page.html"); strings.Contains(body, matrixSecret) {
			t.Errorf("pass %d: cached fragment replayed under -FollowSymLinks (status %d)", i, code)
		}
	}
}
