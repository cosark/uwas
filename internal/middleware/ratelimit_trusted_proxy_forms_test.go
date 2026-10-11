package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// F10900/F10901: a standalone RateLimiter must read its trusted proxies the
// way RealIP does. A bare IP is a valid entry, and every X-Forwarded-For line
// counts, because a proxy may add its own line after a client-supplied one.
func TestRateLimiterTrustedProxyForms(t *testing.T) {
	key := func(proxies []string, remote string, xff ...string) string {
		rl := NewRateLimiter(context.Background(), 10, time.Minute)
		defer rl.Stop()
		rl.SetTrustedProxies(proxies)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		for _, v := range xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		return clientIP(rl, r)
	}
	const client = "198.51.100.7"
	cases := []struct {
		name    string
		proxies []string
		remote  string
		xff     []string
		want    string
	}{
		{"cidr proxy (control)", []string{"10.0.0.0/24"}, "10.0.0.5:1", []string{client}, client},
		{"bare IPv4 proxy", []string{"10.0.0.5"}, "10.0.0.5:1", []string{client}, client},
		{"bare IPv6 proxy", []string{"2001:db8::5"}, "[2001:db8::5]:1", []string{client}, client},
		{"IPv4-mapped bare proxy", []string{"::ffff:10.0.0.5"}, "10.0.0.5:1", []string{client}, client},
		{"two XFF lines, rightmost untrusted wins", []string{"10.0.0.0/24"}, "10.0.0.5:1", []string{"1.2.3.4", client}, client},
		{"untrusted peer's header is ignored", []string{"10.0.0.5"}, "203.0.113.1:1", []string{client}, "203.0.113.1"},
		{"no proxies configured", nil, "10.0.0.5:1", []string{client}, "10.0.0.5"},
	}
	for _, c := range cases {
		if got := key(c.proxies, c.remote, c.xff...); got != c.want {
			t.Errorf("%s: key = %q, want %q", c.name, got, c.want)
		}
	}
}
