package server

// F11100: a domain whose content source changes (root, type, proxy upstream)
// kept serving cached responses of the OLD source until the TTL ended; only a
// removed host was purged (F2680).

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

func TestReloadPurgesCacheWhenContentSourceChanges(t *testing.T) {
	dir := t.TempDir()
	rootA := filepath.Join(dir, "a")
	rootB := filepath.Join(dir, "b")
	for _, p := range []string{rootA, rootB} {
		os.MkdirAll(p, 0o755)
	}
	os.WriteFile(filepath.Join(rootA, "page.txt"), []byte("CONTENT-A"), 0o644)
	os.WriteFile(filepath.Join(rootB, "page.txt"), []byte("CONTENT-B"), 0o644)
	var hits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		fmt.Fprint(w, "ORIGIN-PROXY")
	}))
	defer origin.Close()

	cfgPath := filepath.Join(dir, "uwas.yaml")
	write := func(domainBlock string) {
		y := fmt.Sprintf("global:\n  log_level: error\n  log_format: text\n  web_root: %s\n  cache:\n    enabled: true\n    memory_limit: 16MB\n    default_ttl: 3600\ndomains:\n%s", dir, domainBlock)
		if err := os.WriteFile(cfgPath, []byte(y), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	static := func(root string) string {
		return fmt.Sprintf("  - host: s.test\n    type: static\n    root: %s\n    ssl:\n      mode: \"off\"\n    cache:\n      enabled: true\n      ttl: 3600\n  - host: k.test\n    type: static\n    root: %s\n    ssl:\n      mode: \"off\"\n    cache:\n      enabled: true\n      ttl: 3600\n", root, rootA)
	}
	write(static(rootA))
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, logger.New("error", "text"))
	s.SetConfigPath(cfgPath)
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	get := func(host string) (string, string) {
		req := httptest.NewRequest(http.MethodGet, "/page.txt", nil)
		req.Host = host
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec.Body.String(), rec.Header().Get("X-Cache")
	}
	get("s.test")
	get("k.test")
	b, xc := get("s.test")
	kb, kxc := get("k.test")
	if b != "CONTENT-A" || xc != "HIT" || kb != "CONTENT-A" || kxc != "HIT" {
		t.Fatalf("setup: s=%q/%q k=%q/%q, want CONTENT-A HIT for both", b, xc, kb, kxc)
	}

	// Case 1: root changes A -> B for s.test; k.test unchanged.
	write(static(rootB))
	if err := s.reload(); err != nil {
		t.Fatal(err)
	}
	got1, _ := get("s.test")
	got2, k2 := get("k.test")
	_ = got2
	if got1 != "CONTENT-B" {
		t.Errorf("after the root changed s.test served %q, want CONTENT-B", got1)
	}
	if k2 != "HIT" {
		t.Errorf("unchanged host k.test lost its cache entry: X-Cache=%q", k2)
	}

	// Case 2: type changes static -> proxy.
	proxyBlock := strings.Replace(static(rootB), "  - host: s.test\n    type: static\n    root: "+rootB+"\n", "  - host: s.test\n    type: proxy\n    proxy:\n      upstreams:\n        - address: "+origin.URL+"\n    allow_private_upstreams_placeholder: x\n", 1)
	proxyBlock = strings.Replace(proxyBlock, "    allow_private_upstreams_placeholder: x\n", "", 1)
	proxyBlock = strings.Replace(proxyBlock, "      upstreams:\n", "      allow_private_upstreams: true\n      upstreams:\n", 1)
	write(proxyBlock)
	if err := s.reload(); err != nil {
		t.Fatal(err)
	}
	got3, _ := get("s.test")
	if got3 != "ORIGIN-PROXY" {
		t.Errorf("after static->proxy s.test served %q (origin hits=%d), want ORIGIN-PROXY", got3, hits)
	}
	// A reload that changes nothing must keep the cache warm.
	if err := s.reload(); err != nil {
		t.Fatal(err)
	}
	get("k.test")
	if _, kx := get("k.test"); kx != "HIT" {
		t.Errorf("unchanged k.test lost its entry after a no-op reload: X-Cache=%q", kx)
	}
}
