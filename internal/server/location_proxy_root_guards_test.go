package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F3900: a location proxy_pass forwarded the client's own Forwarded,
// X-Real-IP, X-Forwarded-Proto and X-Forwarded-Port to the upstream; the domain
// proxy overwrites or strips them.
func TestLocationProxyOverwritesClientForwardingHeaders(t *testing.T) {
	var mu sync.Mutex
	var got http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Clone()
		mu.Unlock()
		fmt.Fprint(w, "UP")
	}))
	defer up.Close()
	s := nonCanonServer(t, "", fmt.Sprintf(`    proxy: {allow_private_upstreams: true}
    locations:
      - match: /api/
        proxy_pass: %s
`, up.URL))
	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	req.Host = "a.test"
	req.RemoteAddr = "192.0.2.5:1"
	req.Header.Set("User-Agent", "uwas-test")
	req.Header.Set("X-Real-IP", "10.9.9.9")
	req.Header.Set("Forwarded", "for=10.9.9.9;proto=https")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Port", "8443")
	req.Header.Set("X-Forwarded-For", "10.9.9.9")
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	mu.Lock()
	h := got
	mu.Unlock()
	if rec.Code != 200 || h == nil {
		t.Fatalf("request failed: %d", rec.Code)
	}
	if v := h.Get("X-Forwarded-For"); v != "192.0.2.5" {
		t.Errorf("X-Forwarded-For = %q, want 192.0.2.5", v)
	}
	if v := h.Get("X-Real-IP"); v != "192.0.2.5" {
		t.Errorf("X-Real-IP = %q, want 192.0.2.5", v)
	}
	if v := h.Get("X-Forwarded-Proto"); v != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want http", v)
	}
	for _, k := range []string{"Forwarded", "X-Forwarded-Port"} {
		if v := h.Get(k); v != "" {
			t.Errorf("%s = %q, want it stripped", k, v)
		}
	}
}

// F3901: a location root inside the doc root skipped the doc root's .htaccess
// <FilesMatch> / Require denies that the main static path enforces.
func f3901Server(t *testing.T, locRootOutside bool) *Server {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "site")
	os.MkdirAll(filepath.Join(root, "private"), 0o755)
	os.WriteFile(filepath.Join(root, "index.html"), []byte("ok"), 0o644)
	os.WriteFile(filepath.Join(root, "private", "dump.sql"), []byte("SECRET"), 0o644)
	os.WriteFile(filepath.Join(root, "private", "ok.txt"), []byte("OK"), 0o644)
	os.WriteFile(filepath.Join(root, ".htaccess"), []byte("<FilesMatch \"\\.sql$\">\nRequire all denied\n</FilesMatch>\n"), 0o644)
	locRoot := filepath.Join(root, "private")
	if locRootOutside {
		locRoot = filepath.Join(dir, "outside")
		os.MkdirAll(locRoot, 0o755)
		os.WriteFile(filepath.Join(locRoot, "dump.sql"), []byte("PUBLIC"), 0o644)
	}
	y := fmt.Sprintf(`global:
  worker_count: "1"
  log_level: error
  log_format: text
domains:
  - host: a.test
    type: static
    root: %s
    ssl: {mode: "off"}
    locations:
      - match: /pub/
        root: %s
`, root, locRoot)
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

func f3901Get(s *Server, path string) int {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "a.test"
	req.RemoteAddr = "192.0.2.5:1"
	req.Header.Set("User-Agent", "uwas-test")
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec.Code
}

func TestLocationRootHonoursHtaccessDeny(t *testing.T) {
	s := f3901Server(t, false)
	if c := f3901Get(s, "/private/dump.sql"); c != http.StatusForbidden {
		t.Fatalf("control: main root /private/dump.sql = %d, want 403", c)
	}
	if c := f3901Get(s, "/pub/ok.txt"); c != http.StatusOK {
		t.Fatalf("control: /pub/ok.txt = %d, want 200", c)
	}
	for _, p := range []string{"/pub/dump.sql", "//pub/dump.sql", "/x/../pub/dump.sql"} {
		if c := f3901Get(s, p); c != http.StatusForbidden {
			t.Errorf("%s = %d, want 403", p, c)
		}
	}
}

// A location root outside the doc root is not under the doc root's .htaccess.
func TestLocationRootOutsideDocRootIgnoresDocRootHtaccess(t *testing.T) {
	s := f3901Server(t, true)
	if c := f3901Get(s, "/pub/dump.sql"); c != http.StatusOK {
		t.Errorf("/pub/dump.sql = %d, want 200", c)
	}
}
