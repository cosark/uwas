package server

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

// F17402: the ESI fragment cache is keyed by host and path alone, so a fragment
// an allowed client pulled in was replayed to a client the .htaccess denies.
func TestESIFragmentCacheHonoursHtaccessPerClient(t *testing.T) {
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "priv"), 0o755))
	must(os.WriteFile(filepath.Join(root, "priv/.htaccess"), []byte("Require ip 10.0.0.0/8\n"), 0o644))
	must(os.WriteFile(filepath.Join(root, "priv/frag.txt"), []byte("INTERNAL-FRAGMENT"), 0o644))
	must(os.WriteFile(filepath.Join(root, "page.html"),
		[]byte(`<html><body>X<!--esi <esi:include src="/priv/frag.txt"/> -->Y</body></html>`), 0o644))
	s := newMatrixCacheServer(t, config.Domain{Host: "s.test", Type: "static", Root: root,
		SSL: config.SSLConfig{Mode: "off"}, Cache: config.DomainCache{Enabled: true, TTL: 300, ESI: true}})

	get := func(remote string) string {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/page.html", nil)
		req.Host = "s.test"
		req.RemoteAddr = remote + ":4000"
		req.Header.Set("User-Agent", "uwas-test")
		s.handleRequest(rec, req)
		return rec.Body.String()
	}
	get("10.1.2.3") // fill: page template
	if body := get("10.1.2.3"); !strings.Contains(body, "INTERNAL-FRAGMENT") {
		t.Fatalf("control premise broken: allowed client did not receive the fragment (%q)", body)
	}
	for i := 0; i < 2; i++ {
		if body := get("203.0.113.9"); strings.Contains(body, "INTERNAL-FRAGMENT") {
			t.Fatalf("pass %d: a denied client received the cached fragment: %q", i, body)
		}
	}
}
