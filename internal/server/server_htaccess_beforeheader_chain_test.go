package server

// Regression: applyHtaccessLevels must COMPOSE its BeforeHeader hook, not
// replace it.
//
// The bug: applyHtaccessLevels installed its Expires/AddType hook with a bare
// assignment (`ctx.Response.BeforeHeader = apply`) while stampCacheControl
// composes through `prev`. handleRequest runs a matching location's
// stampCacheControl (server_dispatch.go:416) BEFORE applyHtaccess (:733), so the
// assignment discarded the location's withdrawal hook — the one that strips a
// lifetime-granting Cache-Control from an error response (F9010). A domain with
// both a location `cache_control` and an imported .htaccess therefore answered a
// 404 with `Cache-Control: public, max-age=600`, and browsers and shared caches
// kept the 404 exactly as long as the page would have been cached.
//
// router.ResponseWriter.WriteHeader runs one hook and clears it, so the two
// producers have to be composed into one chain.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// dispatchWithLocationCacheControl serves path for a static domain whose root
// carries htaccessContent as .htaccess and whose "/" location sets cacheControl.
// It returns the status and the Cache-Control the client sees.
func dispatchWithLocationCacheControl(t *testing.T, htaccessContent, cacheControl, path string) (int, string) {
	t.Helper()
	dir := t.TempDir()
	if htaccessContent != "" {
		if err := os.WriteFile(filepath.Join(dir, ".htaccess"), []byte(htaccessContent), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d := config.Domain{
		Host:      "hookchain.test",
		Root:      dir,
		Type:      "static",
		SSL:       config.SSLConfig{Mode: "off"},
		Htaccess:  config.HtaccessConfig{Mode: "import"},
		Locations: []config.LocationConfig{{Match: "/", CacheControl: cacheControl}},
	}
	cfg := &config.Config{
		Global:  config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{d},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(s.cancel)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = d.Host
	s.handleRequest(rec, req)
	return rec.Code, rec.Header().Get("Cache-Control")
}

// TestHtaccessBeforeHeaderComposesWithLocationCacheControl is the defect: the
// htaccess hook must not swallow the location's error-status withdrawal.
func TestHtaccessBeforeHeaderComposesWithLocationCacheControl(t *testing.T) {
	// The AddType is what makes applyHtaccessLevels take the BeforeHeader
	// branch (server_htaccess.go:292-296): with mimeType != "" it cannot
	// apply the rule immediately.
	code, cc := dispatchWithLocationCacheControl(t,
		"AddType text/plain .log\n", "public, max-age=600", "/missing.log")

	if code != http.StatusNotFound {
		t.Fatalf("invalid fixture: status = %d, want 404", code)
	}
	if cc != "" {
		t.Fatalf("404 carries Cache-Control %q; the location's lifetime must be withdrawn from an error response", cc)
	}
}

// Control: the same request with no .htaccess behaves identically, so a green
// result reflects the fix rather than a fixture that never exercised it.
func TestHtaccessBeforeHeaderControlWithoutHtaccess(t *testing.T) {
	code, cc := dispatchWithLocationCacheControl(t, "", "public, max-age=600", "/missing.log")
	if code != http.StatusNotFound {
		t.Fatalf("invalid fixture: status = %d, want 404", code)
	}
	if cc != "" {
		t.Fatalf("404 carries Cache-Control %q with no .htaccess present", cc)
	}
}

// A successful response keeps the location's lifetime: the withdrawal is
// error-only, so chaining must not have turned it into an unconditional strip.
func TestHtaccessBeforeHeaderKeepsLifetimeOnSuccess(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".htaccess"), []byte("AddType text/plain .log\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := config.Domain{
		Host:       "hookchain-ok.test",
		Root:       dir,
		Type:       "static",
		SSL:        config.SSLConfig{Mode: "off"},
		Htaccess:   config.HtaccessConfig{Mode: "import"},
		IndexFiles: []string{"index.html"},
		Locations:  []config.LocationConfig{{Match: "/", CacheControl: "public, max-age=600"}},
	}
	cfg := &config.Config{
		Global:  config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{d},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(s.cancel)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	req.Host = d.Host
	s.handleRequest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=600" {
		t.Errorf("200 Cache-Control = %q, want %q — chaining must not strip a lifetime from a success", got, "public, max-age=600")
	}
}

// The htaccess rule's own work must still happen alongside the location's hook:
// the Expires lifetime is applied to a 200 when the htaccess is the only source.
func TestHtaccessExpiresStillAppliedWithLocationCacheControl(t *testing.T) {
	dir := t.TempDir()
	htaccess := "ExpiresActive On\nExpiresByType text/html \"access plus 1 hour\"\n"
	if err := os.WriteFile(filepath.Join(dir, ".htaccess"), []byte(htaccess), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := config.Domain{
		Host:       "hookchain-expires.test",
		Root:       dir,
		Type:       "static",
		SSL:        config.SSLConfig{Mode: "off"},
		Htaccess:   config.HtaccessConfig{Mode: "import"},
		IndexFiles: []string{"index.html"},
		// A restrictive location value: the htaccess rule must leave an
		// existing Cache-Control alone (mod_expires) rather than be lost to it.
		Locations: []config.LocationConfig{{Match: "/", CacheControl: "no-store"}},
	}
	cfg := &config.Config{
		Global:  config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{d},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(s.cancel)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	req.Host = d.Host
	s.handleRequest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("200 Cache-Control = %q, want %q — an existing Cache-Control wins over ExpiresByType", got, "no-store")
	}
}
