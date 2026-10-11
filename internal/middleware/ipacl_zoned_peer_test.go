package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// F10300: a link-local IPv6 peer arrives zoned ("[fe80::1%eth0]:5000"), which
// net.ParseIP rejects. The ACL then answered "cannot determine IP" and refused
// the peer even when it was whitelisted or not blacklisted.
func TestIPACLZonedLinkLocalPeer(t *testing.T) {
	status := func(g func(http.ResponseWriter, *http.Request) bool, remote string) int {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		if g(w, r) {
			return http.StatusOK
		}
		return w.Code
	}
	black := IPACLGuard(IPACLConfig{Blacklist: []string{"203.0.113.0/24", "fe80::2/128"}})
	white := IPACLGuard(IPACLConfig{Whitelist: []string{"fe80::/10"}})

	cases := []struct {
		name   string
		guard  func(http.ResponseWriter, *http.Request) bool
		remote string
		want   int
	}{
		{"unzoned not blacklisted", black, "[2001:db8::1]:5000", 200},
		{"zoned not blacklisted", black, "[fe80::1%eth0]:5000", 200},
		{"zoned blacklisted address", black, "[fe80::2%eth0]:5000", 403},
		{"blacklisted v4 still denied", black, "203.0.113.9:5000", 403},
		{"unzoned whitelisted", white, "[fe80::1]:5000", 200},
		{"zoned whitelisted", white, "[fe80::1%eth0]:5000", 200},
		{"zoned outside whitelist", white, "[2001:db8::1%eth0]:5000", 403},
		{"garbage still refused", black, "not-an-ip", 403},
	}
	for _, c := range cases {
		if got := status(c.guard, c.remote); got != c.want {
			t.Errorf("%s (%s): status %d, want %d", c.name, c.remote, got, c.want)
		}
	}

	// The middleware form shares the helper.
	h := IPACL(IPACLConfig{Blacklist: []string{"203.0.113.0/24"}})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[fe80::1%eth0]:5000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("IPACL middleware refused a zoned peer: %d", w.Code)
	}
}
