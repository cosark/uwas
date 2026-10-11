package admin

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/admin/authmw"
	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
	"github.com/uwaserver/uwas/internal/metrics"
	"github.com/uwaserver/uwas/internal/middleware"
)

// noAuthChain is the production handler chain of an admin API that has no
// credentials configured (the loopback-only first-run mode).
func noAuthChain(t *testing.T, apiKey string) http.Handler {
	t.Helper()
	cfg := &config.Config{Global: config.GlobalConfig{Admin: config.AdminConfig{Listen: "127.0.0.1:0", APIKey: apiKey}}}
	s := New(cfg, logger.New("error", "text"), metrics.New())
	s.configPath = filepath.Join(t.TempDir(), "uwas.yaml")
	return middleware.RequestID()(s.authMiddleware(requireJSONMiddleware(s.mux)))
}

func chainDo(h http.Handler, method, path, body, ctype string, hdr map[string]string) int {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:50000"
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	for k, v := range hdr {
		if k == "Host" {
			r.Host = v
			continue
		}
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code
}

// F15800: with no credentials the auth middleware injected a virtual admin and
// returned before any Origin check. Any web page the operator visited could
// then write to the admin API (a cross-site form POST to an /import or /upload
// path needs no preflight), and a DNS-rebound name could do anything, because
// the Origin check compares against the request's own Host header.
func TestNoAuthAdminRefusesBrowserOriginatedWrites(t *testing.T) {
	h := noAuthChain(t, "")
	const json = "application/json"
	evil := "https://evil.example"
	cases := []struct {
		name   string
		method string
		path   string
		ctype  string
		hdr    map[string]string
		want   int
	}{
		{"curl-style client, no Origin", "PUT", "/api/v1/settings/branding", json, map[string]string{"Host": "127.0.0.1:9443"}, 200},
		{"dashboard origin", "PUT", "/api/v1/settings/branding", json, map[string]string{"Host": "127.0.0.1:9443", "Origin": "http://127.0.0.1:9443"}, 200},
		{"localhost dev origin", "PUT", "/api/v1/settings/branding", json, map[string]string{"Host": "localhost:9443", "Origin": "http://localhost:5173"}, 200},
		{"cross-site JSON write", "PUT", "/api/v1/settings/branding", json, map[string]string{"Host": "127.0.0.1:9443", "Origin": evil}, 403},
		{"cross-site simple POST to an /import path", "POST", "/api/v1/domains/import", "text/plain", map[string]string{"Host": "127.0.0.1:9443", "Origin": evil}, 403},
		{"cross-site simple POST to an /upload path", "POST", "/api/v1/files/x.test/upload", "multipart/form-data; boundary=b", map[string]string{"Host": "127.0.0.1:9443", "Origin": evil}, 403},
		{"cross-site DELETE", "DELETE", "/api/v1/domains/x.test", json, map[string]string{"Host": "127.0.0.1:9443", "Origin": evil}, 403},
		{"DNS rebinding, same-origin to the attacker name", "PUT", "/api/v1/settings/branding", json, map[string]string{"Host": "evil.example:9443", "Origin": "http://evil.example:9443"}, 403},
		{"DNS rebinding with X-Requested-With", "PUT", "/api/v1/settings/branding", json, map[string]string{"Host": "evil.example:9443", "X-Requested-With": "XMLHttpRequest"}, 403},
		{"DNS rebinding read", "GET", "/api/v1/stats", "", map[string]string{"Host": "evil.example:9443"}, 403},
		{"cross-site read still unreadable, not blocked here", "GET", "/api/v1/stats", "", map[string]string{"Host": "127.0.0.1:9443", "Origin": evil}, 200},
	}
	for _, c := range cases {
		body := ""
		if c.method != "GET" {
			body = `{"name":"x"}`
		}
		if got := chainDo(h, c.method, c.path, body, c.ctype, c.hdr); got != c.want {
			t.Errorf("%s: %s %s = %d, want %d", c.name, c.method, c.path, got, c.want)
		}
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost": true, "localhost:9443": true, "LOCALHOST.": true, "app.localhost:80": true,
		"127.0.0.1": true, "127.0.0.1:9443": true, "127.1.2.3": true, "[::1]": true, "[::1]:9443": true,
		"evil.example": false, "evil.example:9443": false, "localhost.evil.example": false,
		"127.0.0.1.evil.example": false, "10.0.0.5:9443": false, "": false, "[2001:db8::1]:9443": false,
	} {
		if got := authmw.IsLoopbackHost(host); got != want {
			t.Errorf("IsLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

// The guard belongs to the credential-less mode only: a configured API key
// is the protection everywhere else, and operators reach those servers by name.
func TestConfiguredAdminAPIIgnoresHostNames(t *testing.T) {
	h := noAuthChain(t, "key-0123456789abcdef")
	hdr := map[string]string{"Host": "admin.example.com", "Authorization": "Bearer key-0123456789abcdef"}
	if got := chainDo(h, "GET", "/api/v1/stats", "", "", hdr); got != 200 {
		t.Errorf("keyed request on a public name = %d, want 200", got)
	}
	if got := chainDo(h, "GET", "/api/v1/stats", "", "", map[string]string{"Host": "admin.example.com"}); got != 401 {
		t.Errorf("keyless request on a public name = %d, want 401", got)
	}
}
