package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// F10600: a trusted proxy reached over link-local IPv6 arrives zoned
// ("[fe80::1%eth0]:5"); extractIP rejected the zone, so RealIP treated the peer
// as untrusted, ignored its X-Forwarded-For and every client behind it was
// judged as the proxy's address.
func TestRealIPTrustsZonedLinkLocalProxy(t *testing.T) {
	run := func(remote string) (int, string) {
		var seen string
		h := RealIP([]string{"fe80::/10", "2001:db8::/32"})(
			IPACL(IPACLConfig{Blacklist: []string{"203.0.113.9"}})(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					seen = r.RemoteAddr
				})))
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code, seen
	}
	if code, _ := run("[2001:db8::1]:5"); code != http.StatusForbidden {
		t.Fatalf("control (global-scope proxy): status %d, want 403", code)
	}
	if code, seen := run("[fe80::1%eth0]:5"); code != http.StatusForbidden {
		t.Errorf("zoned link-local proxy: status %d (RemoteAddr %q), want 403 for the blacklisted client behind it", code, seen)
	}

	// An untrusted zoned peer must still be left alone: its header is not believed.
	var seen string
	h := RealIP([]string{"2001:db8::/32"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r.RemoteAddr }))
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[fe80::9%eth0]:5"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if seen != "[fe80::9%eth0]:5" {
		t.Errorf("untrusted zoned peer: RemoteAddr %q, want it unchanged", seen)
	}
}

// The rate limiter's own trusted-proxy check had the same zone blind spot:
// a client behind a zoned trusted proxy was keyed as the proxy's /64.
func TestRateLimiterKeyBehindZonedTrustedProxy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rl := NewRateLimiter(ctx, 5, time.Minute)
	rl.SetTrustedProxies([]string{"fe80::/10"})
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[fe80::1%eth0]:5"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := rl.Key(r); got != "203.0.113.9" {
		t.Errorf("Key = %q, want the client behind the zoned trusted proxy (203.0.113.9)", got)
	}
}
