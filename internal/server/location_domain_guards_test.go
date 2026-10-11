package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

func locGuardServer(t *testing.T, security string) *Server {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "site")
	docs := filepath.Join(dir, "docs")
	for _, d := range []string{root, docs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(root, "index.html"), []byte("ok"), 0o644)
	os.WriteFile(filepath.Join(docs, "x.txt"), []byte("DOCS"), 0o644)
	y := fmt.Sprintf(`global:
  worker_count: "1"
  log_level: error
  log_format: text
domains:
  - host: a.test
    type: static
    root: %s
    ssl: {mode: "off"}
    security:
%s
    locations:
      - match: /docs/
        root: %s
      - match: /old
        redirect: https://example.org/new
`, root, security, docs)
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

func locGuardGet(h http.Handler, ip, path string) int {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "a.test"
	req.RemoteAddr = ip + ":1"
	req.Header.Set("User-Agent", "uwas-test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// F3402: a location's redirect / proxy_pass / root answers the request itself,
// and the domain-wide ip_whitelist, ip_blacklist and rate_limit guards used to
// run only after the location loop, so they did not cover those paths.
func TestLocationHandlersHonourDomainAccessGuards(t *testing.T) {
	s := locGuardServer(t, "      ip_whitelist: [\"10.0.0.0/8\"]")
	if c := locGuardGet(s.handler, "192.0.2.5", "/index.html"); c != http.StatusForbidden {
		t.Fatalf("control: /index.html from outside = %d, want 403", c)
	}
	for _, p := range []string{"/docs/x.txt", "/old", "//docs/x.txt", "/a/../docs/x.txt"} {
		if c := locGuardGet(s.handler, "192.0.2.5", p); c != http.StatusForbidden {
			t.Errorf("whitelist: %s from outside = %d, want 403", p, c)
		}
	}
	if c := locGuardGet(s.handler, "10.1.1.1", "/docs/x.txt"); c != http.StatusOK {
		t.Errorf("whitelisted client /docs/x.txt = %d, want 200", c)
	}
	if c := locGuardGet(s.handler, "10.1.1.1", "/old"); c != http.StatusMovedPermanently {
		t.Errorf("whitelisted client /old = %d, want 301", c)
	}

	s = locGuardServer(t, "      ip_blacklist: [\"192.0.2.0/24\"]")
	if c := locGuardGet(s.handler, "192.0.2.5", "/docs/x.txt"); c != http.StatusForbidden {
		t.Errorf("blacklist: /docs/x.txt = %d, want 403", c)
	}
	if c := locGuardGet(s.handler, "198.51.100.5", "/docs/x.txt"); c != http.StatusOK {
		t.Errorf("blacklist control: other client = %d, want 200", c)
	}

	s = locGuardServer(t, "      rate_limit: {requests: 2, window: 1m}")
	var codes []int
	for i := 0; i < 4; i++ {
		codes = append(codes, locGuardGet(s.handler, "192.0.2.7", "/docs/x.txt"))
	}
	if codes[0] != http.StatusOK || codes[1] != http.StatusOK || codes[2] != http.StatusTooManyRequests || codes[3] != http.StatusTooManyRequests {
		t.Errorf("domain rate_limit 2/min on a location root: %v, want [200 200 429 429]", codes)
	}
}
