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

// Invariants of the public request path that an early return could break
// (R123): the unauthenticated health endpoint sits behind the connection-level
// guards, client-supplied forwarding and ESI headers do not steer decisions,
// and a redirect domain cannot be pointed at another host by the request path.
func TestPublicEntryPathInvariants(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "pub.html"), []byte(`<html><!--esi <esi:include src="/frag.html"/> --></html>`), 0o644)
	os.WriteFile(filepath.Join(dir, "frag.html"), []byte("FRAG"), 0o644)

	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text",
			AutoBlock: config.AutoBlockConfig{Enabled: true},
			Cache:     config.CacheConfig{Enabled: true, MemoryLimit: config.ByteSize(4 << 20), DiskPath: t.TempDir(), DiskLimit: config.ByteSize(4 << 20)}},
		Domains: []config.Domain{
			{Host: "esi.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"},
				Cache: config.DomainCache{Enabled: true, TTL: 60, ESI: true}},
			{Host: "canon.example", Aliases: []string{"www.canon.example"}, CanonicalHost: "www", Type: "static", Root: dir,
				SSL: config.SSLConfig{Mode: "off"}},
			{Host: "red.test", Type: "redirect", SSL: config.SSLConfig{Mode: "off"},
				Redirect: config.RedirectConfig{Target: "https://dest.example", PreservePath: true, Status: 301}},
		},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()

	get := func(host, path, remote string, hdr map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = host
		req.RemoteAddr = remote
		req.Header.Set("User-Agent", "uwas-test")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec
	}

	t.Run("health endpoint is behind the blocked-client gate", func(t *testing.T) {
		if err := s.autoblocker.Block("8.8.8.8", "test", time.Hour); err != nil {
			t.Fatal(err)
		}
		if rec := get("esi.test", "/healthz", "9.9.9.9:1", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"ok"`) {
			t.Errorf("control: /healthz = %d %q", rec.Code, rec.Body.String())
		}
		for _, p := range []string{"/healthz", "/.well-known/health"} {
			if rec := get("esi.test", p, "8.8.8.8:1", nil); rec.Code != 403 {
				t.Errorf("%s from a blocked address = %d, want 403", p, rec.Code)
			}
		}
	})

	t.Run("a client cannot pose as an ESI subrequest", func(t *testing.T) {
		get("esi.test", "/pub.html", "9.9.9.9:1", nil)
		with := get("esi.test", "/pub.html", "9.9.9.9:1", map[string]string{"X-ESI-Subrequest": "true"})
		without := get("esi.test", "/pub.html", "9.9.9.9:1", nil)
		if with.Code != without.Code || with.Body.String() != without.Body.String() {
			t.Errorf("X-ESI-Subrequest changed the response: %d %q vs %d %q",
				with.Code, with.Body.String(), without.Code, without.Body.String())
		}
		if !strings.Contains(with.Body.String(), "FRAG") {
			t.Errorf("fragment not assembled for a request that sent the header: %q", with.Body.String())
		}
	})

	t.Run("redirects ignore client forwarding headers", func(t *testing.T) {
		rec := get("canon.example", "/x?y=1", "9.9.9.9:1", map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "evil.com"})
		if loc := rec.Header().Get("Location"); rec.Code != 301 || loc != "http://www.canon.example/x?y=1" {
			t.Errorf("canonical redirect = %d %q, want 301 http://www.canon.example/x?y=1", rec.Code, loc)
		}
	})

	t.Run("a redirect domain keeps its configured target", func(t *testing.T) {
		for _, p := range []string{"//evil.com/x", "/%0d%0aSet-Cookie:a=b", `/\evil.com`} {
			rec := get("red.test", p, "9.9.9.9:1", nil)
			loc := rec.Header().Get("Location")
			if !strings.HasPrefix(loc, "https://dest.example/") || strings.ContainsAny(loc, "\r\n") {
				t.Errorf("%q redirected to %q", p, loc)
			}
		}
	})
}
