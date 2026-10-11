package admin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
	"github.com/uwaserver/uwas/internal/metrics"
)

// F10700: the failure lockout counts an IPv6 client by its /64, so rotating
// the interface id (or the zone of a link-local peer) cannot dodge it, while
// a neighbouring /64 and IPv4 clients keep their own counters.
func TestAdminLockoutIsKeyedPerIPv6Prefix(t *testing.T) {
	cfg := &config.Config{Global: config.GlobalConfig{Admin: config.AdminConfig{Listen: "127.0.0.1:0", APIKey: "secret-key"}}}
	s := New(cfg, logger.New("error", "text"), metrics.New())
	t.Cleanup(s.stopAudit)
	h := s.authMiddleware(s.mux)

	do := func(key, remote string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/v1/stats", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		req.RemoteAddr = remote
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	for i := 0; i < rateLimitMaxFails; i++ {
		do("wrong", fmt.Sprintf("[2001:db8:1:2::%x]:1000", 0x100+i))
	}
	if got := do("secret-key", "[2001:db8:1:2:ffff::1]:1001"); got != http.StatusTooManyRequests {
		t.Errorf("same /64, new address: status %d, want 429", got)
	}
	if got := do("secret-key", "[2001:db8:1:3::1]:1001"); got != http.StatusOK {
		t.Errorf("neighbouring /64: status %d, want 200", got)
	}
	if got := do("secret-key", "10.0.0.9:1001"); got != http.StatusOK {
		t.Errorf("IPv4 client: status %d, want 200", got)
	}

	for i := 0; i < rateLimitMaxFails; i++ {
		do("wrong", fmt.Sprintf("[fe80::%x%%eth%d]:1000", 0x10+i, i))
	}
	if got := do("secret-key", "[fe80::99%wlan0]:1001"); got != http.StatusTooManyRequests {
		t.Errorf("zoned link-local peers: status %d, want 429", got)
	}
}

func TestLockoutKey(t *testing.T) {
	for in, want := range map[string]string{
		"192.168.1.1":          "192.168.1.1",
		"::ffff:192.168.1.1":   "192.168.1.1",
		"2001:db8:1:2::7":      "2001:db8:1:2::/64",
		"2001:db8:1:2:aaaa::7": "2001:db8:1:2::/64",
		"fe80::1%eth0":         "fe80::/64",
		"stale-ip":             "stale-ip",
	} {
		if got := lockoutKey(in); got != want {
			t.Errorf("lockoutKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// The lockout is keyed on the transport peer: a spoofed X-Forwarded-For or
// X-Real-IP neither dodges a block nor frames another client.
func TestAdminLockoutIgnoresForwardedHeaders(t *testing.T) {
	cfg := &config.Config{Global: config.GlobalConfig{Admin: config.AdminConfig{Listen: "127.0.0.1:0", APIKey: "secret-key"}}}
	s := New(cfg, logger.New("error", "text"), metrics.New())
	t.Cleanup(s.stopAudit)
	h := s.authMiddleware(s.mux)

	do := func(key, remote, xff string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/v1/stats", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("X-Forwarded-For", xff)
		req.Header.Set("X-Real-IP", xff)
		req.RemoteAddr = remote
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < rateLimitMaxFails; i++ {
		do("wrong", "198.51.100.7:1000", fmt.Sprintf("203.0.113.%d", i))
	}
	if got := do("secret-key", "198.51.100.7:1001", "203.0.113.200"); got != http.StatusTooManyRequests {
		t.Errorf("rotating X-Forwarded-For escaped the lockout: status %d, want 429", got)
	}
	if got := do("secret-key", "198.51.100.8:1001", "198.51.100.7"); got != http.StatusOK {
		t.Errorf("spoofed X-Forwarded-For framed another client: status %d, want 200", got)
	}
}
