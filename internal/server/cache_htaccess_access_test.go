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

// F4801: the response cache is consulted before the per-directory .htaccess
// access check, so a client the rule allows filled the cache and every other
// client read the file from it.
func TestCachedResponseHonoursHtaccessIPRule(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "private"), 0o755)
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("ok"), 0o644)
	os.WriteFile(filepath.Join(dir, "pub.txt"), []byte("PUBLIC"), 0o644)
	os.WriteFile(filepath.Join(dir, "private", "data.txt"), []byte("INTERNAL"), 0o644)
	os.WriteFile(filepath.Join(dir, "private", ".htaccess"), []byte("Require ip 203.0.113.0/24\n"), 0o644)
	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text",
			Cache: config.CacheConfig{Enabled: true, MemoryLimit: config.ByteSize(4 << 20), DiskPath: t.TempDir(), DiskLimit: config.ByteSize(4 << 20)}},
		Domains: []config.Domain{{Host: "c.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"},
			Cache: config.DomainCache{Enabled: true, TTL: 60}}},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	get := func(path, ip string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "c.test"
		req.RemoteAddr = ip + ":1"
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec.Code, rec.Header().Get("X-Cache")
	}
	if c, _ := get("/private/data.txt", "192.0.2.5"); c != http.StatusForbidden {
		t.Fatalf("control: cold denied client = %d, want 403", c)
	}
	if c, _ := get("/private/data.txt", "203.0.113.9"); c != http.StatusOK {
		t.Fatalf("allowed client = %d, want 200", c)
	}
	if c, xc := get("/private/data.txt", "203.0.113.10"); c != http.StatusOK || xc != "HIT" {
		t.Errorf("allowed client repeat = %d X-Cache=%q, want 200 HIT", c, xc)
	}
	if c, xc := get("/private/data.txt", "192.0.2.5"); c != http.StatusForbidden {
		t.Errorf("denied client after cache warm = %d X-Cache=%q, want 403", c, xc)
	}
	// An unrestricted file is still served to anyone from the cache.
	get("/pub.txt", "203.0.113.9")
	if c, xc := get("/pub.txt", "192.0.2.5"); c != http.StatusOK || xc != "HIT" {
		t.Errorf("public file = %d X-Cache=%q, want 200 HIT", c, xc)
	}
}
