package server

import (
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

// An ESI include is served by the same guards as a client request for the
// fragment path: location basic_auth and blocked_paths apply, credentials the
// parent carries are honoured, and a credentialed fragment is not shared (F4501).
func TestESIFragmentHonoursPathGuards(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "private"), 0o755)
	write := func(name, body string) { os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644) }
	write("pub.html", `<html><!--esi <esi:include src="/frag.html"/> --></html>`)
	write("frag.html", "PUBLICFRAG")
	write("priv.html", `<html><!--esi <esi:include src="/private/secret.html"/> --></html>`)
	write("private/secret.html", "SECRET")
	write("blk.html", `<html><!--esi <esi:include src="/internal/x.html"/> --></html>`)
	os.MkdirAll(filepath.Join(dir, "internal"), 0o755)
	write("internal/x.html", "BLOCKED")

	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text",
			Cache: config.CacheConfig{Enabled: true, MemoryLimit: config.ByteSize(4 << 20), DiskPath: t.TempDir(), DiskLimit: config.ByteSize(4 << 20)}},
		Domains: []config.Domain{{Host: "esi.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"},
			Cache:    config.DomainCache{Enabled: true, TTL: 60, ESI: true},
			Security: config.SecurityConfig{BlockedPaths: []string{"/internal/"}},
			Locations: []config.LocationConfig{{Match: "/private/", BasicAuth: &config.BasicAuthConfig{Enabled: true,
				Users: map[string]string{"admin": "pw"}}}},
		}},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	get := func(p, auth string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Host = "esi.test"
		req.RemoteAddr = "192.0.2.5:1"
		req.Header.Set("User-Agent", "uwas-test")
		if auth != "" {
			req.SetBasicAuth("admin", auth)
		}
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	twice := func(p, auth string) string { get(p, auth); _, b := get(p, auth); return b }

	if b := twice("/pub.html", ""); !strings.Contains(b, "PUBLICFRAG") {
		t.Fatalf("control: public fragment not assembled: %q", b)
	}
	if b := twice("/priv.html", ""); strings.Contains(b, "SECRET") {
		t.Errorf("protected fragment leaked to unauthenticated client: %q", b)
	}
	if b := twice("/blk.html", ""); strings.Contains(b, "BLOCKED") {
		t.Errorf("blocked_paths fragment leaked: %q", b)
	}
	// Credentials the parent carries are honoured ...
	if b := twice("/priv.html", "pw"); !strings.Contains(b, "SECRET") {
		t.Errorf("authenticated parent did not get its fragment: %q", b)
	}
	// ... and the credentialed fragment is not served to the next anonymous client.
	if b := twice("/priv.html", ""); strings.Contains(b, "SECRET") {
		t.Errorf("credentialed fragment shared with anonymous client: %q", b)
	}
}
