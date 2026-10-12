package server

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

// Guard × replay-path matrix (F17800 series). Each cell asks for content that
// a guard must keep from the requesting client, through handleRequest, with the
// response cache enabled and (where relevant) already filled by an allowed
// client.
func parityGet(s *Server, method, path, remote string, hdr map[string]string) (int, string) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	req.Host = "g.test"
	req.RemoteAddr = remote + ":4000"
	req.Header.Set("User-Agent", "uwas-test")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	s.handleRequest(rec, req)
	return rec.Code, rec.Body.String()
}

func paritySite(t *testing.T) string {
	root := t.TempDir()
	w := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("index.html", "HOME")
	w("private/x.txt", "PRIVATE-BODY")
	w("members/x.txt", "MEMBERS-BODY")
	w("d/index.html", "DIR-INDEX-BODY")
	w("d/.htaccess", "<Files \"index.html\">\nRequire ip 10.0.0.0/8\n</Files>\n")
	w("fm/a.txt", "FILESMATCH-BODY")
	w("fm/.htaccess", "<FilesMatch \"\\.txt$\">\nRequire ip 10.0.0.0/8\n</FilesMatch>\n")
	return root
}

func TestGuardParityMatrix(t *testing.T) {
	root := paritySite(t)
	hash := "$2y$05$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
	dom := config.Domain{Host: "g.test", Type: "static", Root: root, SSL: config.SSLConfig{Mode: "off"},
		Cache:    config.DomainCache{Enabled: true, TTL: 300},
		Security: config.SecurityConfig{BlockedPaths: []string{"/private"}},
		Locations: []config.LocationConfig{{Match: "/members/", BasicAuth: &config.BasicAuthConfig{
			Enabled: true, Users: map[string]string{"u": hash}}}},
		Rewrites: []config.RewriteRule{
			{Match: "^/to-private$", To: "/private/x.txt", Flags: []string{"L"}},
			{Match: "^/to-members$", To: "/members/x.txt", Flags: []string{"L"}},
		},
	}
	s := newMatrixCacheServer(t, dom)

	type cell struct{ name, path, secret, remote string }
	cells := []cell{
		{"direct blocked_paths", "/private/x.txt", "PRIVATE-BODY", "203.0.113.9"},
		{"rewrite -> blocked_paths", "/to-private", "PRIVATE-BODY", "203.0.113.9"},
		{"direct location basic_auth", "/members/x.txt", "MEMBERS-BODY", "203.0.113.9"},
		{"rewrite -> location basic_auth", "/to-members", "MEMBERS-BODY", "203.0.113.9"},
		{"dir index under <Files> deny", "/d/", "DIR-INDEX-BODY", "203.0.113.9"},
		{"FilesMatch deny", "/fm/a.txt", "FILESMATCH-BODY", "203.0.113.9"},
	}
	for _, c := range cells {
		// Fill as an allowed client where the guard is client-based, then ask
		// again as the denied one, twice (second is a cache hit).
		parityGet(s, "GET", c.path, "10.1.2.3", nil)
		for i := 0; i < 2; i++ {
			code, body := parityGet(s, "GET", c.path, c.remote, nil)
			leaked := strings.Contains(body, c.secret)
			t.Logf("%-32s pass %d -> %d leaked=%v", c.name, i, code, leaked)
			// A rewrite rule is operator-written routing: mapping a public URL
			// onto a guarded path is explicit intent, recorded here but not
			// asserted. Every other cell is a guard that must hold.
			if leaked && !strings.HasPrefix(c.name, "rewrite") {
				t.Errorf("%s: pass %d leaked %q to %s (status %d)", c.name, i, c.secret, c.remote, code)
			}
		}
	}
	for _, m := range []string{"HEAD", "OPTIONS", "TRACE", "PUT"} {
		parityGet(s, "GET", "/fm/a.txt", "10.1.2.3", nil)
		code, body := parityGet(s, m, "/fm/a.txt", "203.0.113.9", nil)
		if code == 200 || strings.Contains(body, "FILESMATCH-BODY") {
			t.Errorf("method %s on a cached denied path -> %d %q", m, code, body)
		}
	}
}
