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

// F5100: the cache-hit .htaccess check (F4801) judged the URL as a directory,
// so a <FilesMatch> rule written for the file the URL resolves to (the index
// file, or the SPA fallback) was enforced on a cold request and skipped on a
// cache hit.
func TestCachedResponseHonoursHtaccessRuleForResolvedFile(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "priv"), 0o755)
	os.MkdirAll(filepath.Join(dir, "open"), 0o755)
	os.WriteFile(filepath.Join(dir, "priv", "index.html"), []byte("INTERNAL-INDEX"), 0o644)
	os.WriteFile(filepath.Join(dir, "open", "index.html"), []byte("OPEN-INDEX"), 0o644)
	os.WriteFile(filepath.Join(dir, "priv", ".htaccess"),
		[]byte("<FilesMatch \"^index\\.html$\">\nRequire ip 203.0.113.0/24\n</FilesMatch>\n"), 0o644)

	spa := t.TempDir()
	os.WriteFile(filepath.Join(spa, "index.html"), []byte("SPA-SHELL"), 0o644)
	os.WriteFile(filepath.Join(spa, ".htaccess"),
		[]byte("<FilesMatch \"^index\\.html$\">\nRequire ip 203.0.113.0/24\n</FilesMatch>\n"), 0o644)

	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text",
			Cache: config.CacheConfig{Enabled: true, MemoryLimit: config.ByteSize(4 << 20), DiskPath: t.TempDir(), DiskLimit: config.ByteSize(4 << 20)}},
		Domains: []config.Domain{
			{Host: "c.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"},
				Cache: config.DomainCache{Enabled: true, TTL: 60}},
			{Host: "spa.test", Type: "static", Root: spa, SPAMode: true, SSL: config.SSLConfig{Mode: "off"},
				Cache: config.DomainCache{Enabled: true, TTL: 60}},
		},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	get := func(host, path, ip string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = host
		req.RemoteAddr = ip + ":1"
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec.Code, rec.Header().Get("X-Cache")
	}

	// Controls: cold denied client, and an unrestricted index served from cache.
	if c, _ := get("c.test", "/priv/", "192.0.2.5"); c != http.StatusForbidden {
		t.Fatalf("control: cold denied /priv/ = %d, want 403", c)
	}
	get("c.test", "/open/", "203.0.113.9")
	if c, xc := get("c.test", "/open/", "192.0.2.5"); c != http.StatusOK || xc != "HIT" {
		t.Fatalf("control: /open/ = %d %q, want 200 HIT", c, xc)
	}

	// Index file reached through the directory URL.
	if c, _ := get("c.test", "/priv/", "203.0.113.9"); c != http.StatusOK {
		t.Fatalf("allowed client /priv/ = %d, want 200", c)
	}
	if c, xc := get("c.test", "/priv/", "192.0.2.5"); c != http.StatusForbidden {
		t.Errorf("denied client /priv/ after warm cache = %d X-Cache=%q, want 403", c, xc)
	}

	// SPA fallback: any URL resolves to the guarded index.html.
	if c, _ := get("spa.test", "/app/route", "203.0.113.9"); c != http.StatusOK {
		t.Fatalf("allowed client SPA route = %d, want 200", c)
	}
	if c, xc := get("spa.test", "/app/route", "192.0.2.5"); c != http.StatusForbidden {
		t.Errorf("denied client SPA route after warm cache = %d X-Cache=%q, want 403", c, xc)
	}
}
