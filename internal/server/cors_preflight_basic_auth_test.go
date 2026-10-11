package server

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F15901: a browser sends a CORS preflight without credentials, so basic auth
// answered it 401 and the request it asked about could never be made from a
// page. The preflight is answered ahead of auth; everything else still meets
// auth, and the guards that run before it still apply.
func TestCORSPreflightIsAnsweredAheadOfBasicAuth(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("SECRET-PAGE"), 0o644)
	cors := config.CORSConfig{Enabled: true, AllowedOrigins: []string{"https://app.example"},
		AllowedMethods: []string{"GET", "POST"}, AllowedHeaders: []string{"Authorization"}}
	auth := config.BasicAuthConfig{Enabled: true, Users: map[string]string{"a": "pw"}}

	cfg := &config.Config{Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{
			{Host: "ba.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"}, BasicAuth: auth, CORS: cors},
			{Host: "loc.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"}, CORS: cors,
				Locations: []config.LocationConfig{{Match: "/api/", BasicAuth: &auth}}},
			{Host: "acl.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"}, BasicAuth: auth, CORS: cors,
				Security: config.SecurityConfig{IPWhitelist: []string{"203.0.113.0/24"}}},
			{Host: "blk.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"}, BasicAuth: auth, CORS: cors,
				Security: config.SecurityConfig{BlockedPaths: []string{"/private"}}},
		}}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()

	do := func(method, host, path, origin string, preflight bool, remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Host = host
		req.RemoteAddr = remote
		req.Header.Set("User-Agent", "uwas-test")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if preflight {
			req.Header.Set("Access-Control-Request-Method", "GET")
		}
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec
	}
	const peer = "203.0.113.5:1"

	if rec := do("OPTIONS", "ba.test", "/index.html", "https://app.example", true, peer); rec.Code != 204 ||
		rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Errorf("preflight on a basic-auth domain = %d ACAO=%q, want 204 with the origin allowed",
			rec.Code, rec.Header().Get("Access-Control-Allow-Origin"))
	}
	if rec := do("OPTIONS", "loc.test", "/api/x", "https://app.example", true, peer); rec.Code != 204 {
		t.Errorf("preflight on a location with basic auth = %d, want 204", rec.Code)
	}

	// The request itself still needs credentials and nothing leaks.
	if rec := do("GET", "ba.test", "/index.html", "https://app.example", false, peer); rec.Code != 401 ||
		rec.Body.String() == "SECRET-PAGE" {
		t.Errorf("GET without credentials = %d, want 401", rec.Code)
	}
	// An origin the policy does not list gets no CORS headers, preflight or not.
	if rec := do("OPTIONS", "ba.test", "/index.html", "https://evil.example", true, peer); rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("preflight from an unlisted origin was allowed: %v", rec.Header())
	}
	// A plain OPTIONS (no preflight headers) is not short-circuited.
	if rec := do("OPTIONS", "ba.test", "/index.html", "", false, peer); rec.Code != 401 {
		t.Errorf("plain OPTIONS = %d, want 401 from basic auth", rec.Code)
	}
	// Guards that run ahead of auth still apply to a preflight.
	if rec := do("OPTIONS", "acl.test", "/index.html", "https://app.example", true, "198.51.100.9:1"); rec.Code != 403 {
		t.Errorf("preflight from a denied address = %d, want 403", rec.Code)
	}
	if rec := do("OPTIONS", "blk.test", "/private/x", "https://app.example", true, peer); rec.Code != 403 {
		t.Errorf("preflight on a blocked path = %d, want 403", rec.Code)
	}
}
