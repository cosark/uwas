package middleware

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Characterization (R130): behind a trusted proxy, the address RealIP settles
// on and the rate limiter's bucket identity must name the same client, so a
// forged header cannot move only one of them. Cases are the ones RealIP
// accepts; spoofs from an untrusted peer and unusable values are included to
// show both fall back to the direct peer.
func TestRealIPAndRateLimiterAgreeOnClient(t *testing.T) {
	trusted := []string{"10.0.0.0/8", "2001:db8:ffff::/48"}
	trust := NewRealIPTrust(trusted)
	cases := []struct {
		name string
		peer string
		hdr  [][2]string
		want string // expected client address after RealIP, "" = the peer itself
	}{
		{"rightmost untrusted wins over client-prepended", "10.0.0.1:1", [][2]string{{"X-Forwarded-For", "1.1.1.1, 203.0.113.9"}}, "203.0.113.9"},
		{"two header lines", "10.0.0.1:1", [][2]string{{"X-Forwarded-For", "1.1.1.1"}, {"X-Forwarded-For", "203.0.113.9"}}, "203.0.113.9"},
		{"port suffix", "10.0.0.1:1", [][2]string{{"X-Forwarded-For", "203.0.113.9:5555"}}, "203.0.113.9"},
		{"bracketed v6 with port", "10.0.0.1:1", [][2]string{{"X-Forwarded-For", "[2001:db8::9]:443"}}, "2001:db8::9"},
		{"mapped v4", "10.0.0.1:1", [][2]string{{"X-Forwarded-For", "::ffff:203.0.113.9"}}, "203.0.113.9"},
		{"trusted hop skipped", "10.0.0.1:1", [][2]string{{"X-Forwarded-For", "203.0.113.9, 10.0.0.2"}}, "203.0.113.9"},
		{"x-real-ip alone", "10.0.0.1:1", [][2]string{{"X-Real-IP", "198.51.100.2"}}, "198.51.100.2"},
		{"x-real-ip disagreeing with xff", "10.0.0.1:1", [][2]string{{"X-Real-IP", "198.51.100.2"}, {"X-Forwarded-For", "203.0.113.9"}}, "203.0.113.9"},
		{"v6 trusted peer", "[2001:db8:ffff::5]:1", [][2]string{{"X-Forwarded-For", "203.0.113.9"}}, "203.0.113.9"},
		{"mapped trusted peer", "[::ffff:10.0.0.1]:1", [][2]string{{"X-Forwarded-For", "203.0.113.9"}}, "203.0.113.9"},
		{"untrusted peer cannot spoof", "198.51.100.50:1", [][2]string{{"X-Forwarded-For", "203.0.113.9"}, {"X-Real-IP", "203.0.113.10"}}, ""},
		{"zoned xff value unusable", "10.0.0.1:1", [][2]string{{"X-Forwarded-For", "fe80::1%eth0"}}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rl := NewRateLimiter(context.Background(), 5, time.Minute)
			defer rl.Stop()
			rl.SetTrustedProxies(trusted)

			var seen string
			h := RealIPDynamic(trust)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = r.RemoteAddr
				// The limiter runs after RealIP in the server's chain.
				if got, want := rl.Key(r), rateAddr(hostOnly(r.RemoteAddr)); got != want {
					t.Errorf("rate limiter keyed %q, RealIP resolved %q", got, want)
				}
			}))
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = c.peer
			for _, kv := range c.hdr {
				req.Header.Add(kv[0], kv[1])
			}
			h.ServeHTTP(httptest.NewRecorder(), req)

			want := c.want
			if want == "" {
				want = hostOnly(c.peer)
			}
			if got := hostOnly(seen); !net.ParseIP(got).Equal(net.ParseIP(want)) {
				t.Fatalf("client address %q, want %q", got, want)
			}
		})
	}
}

func hostOnly(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}
