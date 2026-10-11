package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/auth"
	"github.com/uwaserver/uwas/internal/config"
)

// F13400: the file routes authorise the {domain} path value by its canonical
// spelling (case, trailing dot, "bücher.example" vs "xn--bcher-kva.example")
// but resolved the directory with an exact string match. A spelling other than
// the stored one therefore missed the configured domain, fell back to
// <web_root>/<spelling>/public_html and the file manager worked, and created
// directories, somewhere the site does not serve from.
func TestFileRoutesResolveHostSpellingsToTheConfiguredRoot(t *testing.T) {
	cases := []struct {
		name, stored, spelling string
	}{
		{"punycode path for a Unicode host", "bücher.example", "xn--bcher-kva.example"},
		{"upper case path", "mine.com", "Mine.COM"},
		{"trailing dot path", "mine.com", "mine.com."},
	}
	for _, c := range cases {
		dir := t.TempDir()
		custom := filepath.Join(dir, "custom", "site") // not <web_root>/<host>/public_html
		if err := os.MkdirAll(custom, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(custom, "marker.txt"), []byte("real"), 0o644); err != nil {
			t.Fatal(err)
		}
		webRoot := filepath.Join(dir, "www")
		if err := os.MkdirAll(webRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		s := testServerFromConfig(t, &config.Config{
			Global:  config.GlobalConfig{WebRoot: webRoot, LogLevel: "error", LogFormat: "text"},
			Domains: []config.Domain{{Host: c.stored, Type: "static", Root: custom, SSL: config.SSLConfig{Mode: "off"}}},
		})
		mgr, err := auth.NewManager(t.TempDir(), "adminkey-0123456789")
		if err != nil {
			t.Fatal(err)
		}
		s.authMgr = mgr // the real manager compares hosts canonically (F13100)

		do := func(method, host, tail, body string) (int, string) {
			r := httptest.NewRequest(method, "/api/v1/files/"+url.PathEscape(host)+"/"+tail, strings.NewReader(body))
			r = r.WithContext(auth.WithUser(r.Context(), &auth.User{ID: "u", Username: "u", Role: auth.RoleReseller, Enabled: true, Domains: []string{c.stored}}))
			r.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			s.mux.ServeHTTP(rec, r)
			return rec.Code, rec.Body.String()
		}

		// Control: the stored spelling reaches the configured root.
		if code, body := do(http.MethodGet, c.stored, "list?path=.", ""); code != http.StatusOK || !strings.Contains(body, "marker.txt") {
			t.Fatalf("%s: control list = %d %q, want the configured root", c.name, code, body)
		}

		code, body := do(http.MethodGet, c.spelling, "list?path=.", "")
		if code != http.StatusOK || !strings.Contains(body, "marker.txt") {
			t.Errorf("%s: list via %q = %d %q, want the configured root (marker.txt)", c.name, c.spelling, code, body)
		}
		// Control: a write through the stored spelling lands in the root.
		if code, body := do(http.MethodPut, c.stored, "write", `{"path":"ctl.txt","content":"x"}`); code != http.StatusOK {
			t.Fatalf("%s: control write = %d %q", c.name, code, body)
		}
		if _, err := os.Stat(filepath.Join(custom, "ctl.txt")); err != nil {
			t.Fatalf("%s: control write did not land in the configured root", c.name)
		}
		do(http.MethodPut, c.spelling, "write", `{"path":"new.txt","content":"x"}`)
		if _, err := os.Stat(filepath.Join(custom, "new.txt")); err != nil {
			t.Errorf("%s: write via %q did not land in the configured root", c.name, c.spelling)
		}
		// Nothing may be created under a directory named after the spelling.
		entries, _ := os.ReadDir(webRoot)
		for _, e := range entries {
			t.Errorf("%s: stray directory %q created under web_root", c.name, e.Name())
		}
	}
}

// F13400: the PHP and WordPress routes took the domain root from the same
// exact-match lookup. For another spelling of the host it returned "", so a PHP
// pool was assigned with no document root (its generated ini then carries no
// open_basedir at all) and a WordPress install fell back to
// <web_root>/<spelling>/public_html.
func TestPHPAndWordPressRootLookupsAcceptHostSpellings(t *testing.T) {
	s := testServerFromConfig(t, &config.Config{
		Global:  config.GlobalConfig{WebRoot: t.TempDir(), LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{{Host: "bücher.example", Type: "php", Root: "/srv/custom/site", SSL: config.SSLConfig{Mode: "off"}}},
	})
	for _, spelling := range []string{"bücher.example", "xn--bcher-kva.example", "BÜCHER.example", "xn--bcher-kva.example."} {
		if got := (&phpDeps{s: s}).DomainRoot(spelling); got != "/srv/custom/site" {
			t.Errorf("php DomainRoot(%q) = %q, want /srv/custom/site", spelling, got)
		}
		if got := (&wpDeps{s: s}).DomainRoot(spelling); got != "/srv/custom/site" {
			t.Errorf("wordpress DomainRoot(%q) = %q, want /srv/custom/site", spelling, got)
		}
	}
	// Control: an unrelated host still has no root.
	if got := (&phpDeps{s: s}).DomainRoot("xn--bcher-kva2.example"); got != "" {
		t.Errorf("unrelated host resolved to %q", got)
	}
	// SetDomainFPMAddress must update the configured domain, not silently miss it.
	(&phpDeps{s: s}).SetDomainFPMAddress("xn--bcher-kva.example", "127.0.0.1:9001")
	s.configMu.RLock()
	got := s.config.Domains[0].PHP.FPMAddress
	s.configMu.RUnlock()
	if got != "127.0.0.1:9001" {
		t.Errorf("SetDomainFPMAddress via the punycode spelling left FPMAddress = %q", got)
	}
}
