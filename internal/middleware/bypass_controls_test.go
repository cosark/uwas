package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/logger"
)

// Pins that no middleware has an early return keyed on something the client
// chooses (a method, an Upgrade or Accept header, a path prefix, a forwarded
// address). F15800 was one such skip; these are the ones that were read and
// found closed (F16000 audit).

func ok200() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
}

type shape struct {
	name   string
	method string
	hdr    map[string]string
}

var requestShapes = []shape{
	{"plain GET", "GET", nil},
	{"HEAD", "HEAD", nil},
	{"OPTIONS", "OPTIONS", nil},
	{"Upgrade websocket", "GET", map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"}},
	{"event stream", "GET", map[string]string{"Accept": "text/event-stream"}},
	{"Range", "GET", map[string]string{"Range": "bytes=0-"}},
	{"Expect 100-continue", "POST", map[string]string{"Expect": "100-continue"}},
	{"method override", "POST", map[string]string{"X-HTTP-Method-Override": "GET"}},
}

func newShaped(s shape, target string) *http.Request {
	r := httptest.NewRequest(s.method, target, nil)
	r.RemoteAddr = "198.51.100.7:4000"
	for k, v := range s.hdr {
		r.Header.Set(k, v)
	}
	return r
}

func TestRateLimitCountsEveryRequestShape(t *testing.T) {
	for _, s := range requestShapes {
		t.Run(s.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h := RateLimit(ctx, 2, time.Minute)(ok200())
			var codes []int
			for i := 0; i < 3; i++ {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, newShaped(s, "/x"))
				codes = append(codes, w.Code)
			}
			if codes[2] != http.StatusTooManyRequests {
				t.Errorf("codes = %v, the third request was not limited", codes)
			}
		})
	}
}

func TestWAFURLScanIgnoresRequestShape(t *testing.T) {
	guard := DomainWAFGuard(logger.New("error", "text"), nil, nil, nil)
	for _, s := range requestShapes {
		t.Run(s.name, func(t *testing.T) {
			r := newShaped(s, "/search?q="+"1'+UNION+SELECT+password+FROM+users--")
			if guard(httptest.NewRecorder(), r) {
				t.Error("an attack in the URL was let through")
			}
		})
	}
}

func TestBasicAuthHasNoPathExemption(t *testing.T) {
	h := BasicAuth(map[string]string{"u": "p"}, "")(ok200())
	for _, p := range []string{
		"/", "/.well-known/acme-challenge/token", "/.well-known/../admin",
		"/robots.txt", "/favicon.ico", "/sitemap.xml", "//admin",
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", p, nil))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d without credentials, want 401", p, w.Code)
		}
	}
}

func TestIPACLIgnoresForwardedAddresses(t *testing.T) {
	forged := map[string]string{
		"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1",
		"Forwarded": "for=127.0.0.1", "CF-Connecting-IP": "127.0.0.1",
	}
	run := func(cfg IPACLConfig, remote string) int {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		for k, v := range forged {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		IPACL(cfg)(ok200()).ServeHTTP(w, r)
		return w.Code
	}
	if c := run(IPACLConfig{Blacklist: []string{"203.0.113.0/24"}}, "203.0.113.9:1"); c != http.StatusForbidden {
		t.Errorf("blacklisted peer with a forged loopback header: %d, want 403", c)
	}
	if c := run(IPACLConfig{Whitelist: []string{"127.0.0.0/8"}}, "203.0.113.9:1"); c != http.StatusForbidden {
		t.Errorf("peer outside the whitelist with a forged loopback header: %d, want 403", c)
	}
}

func TestGeoIPDecidesOnTheTransportAddress(t *testing.T) {
	db := filepath.Join(t.TempDir(), "geo.json")
	if err := os.WriteFile(db, []byte(`{"203.0.113.0/24":"XX","198.51.100.0/24":"YY"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h := GeoIP(GeoIPConfig{BlockedCountries: []string{"XX"}, DBPath: db})(ok200())
	for _, hdr := range []map[string]string{
		nil,
		{"X-Forwarded-For": "198.51.100.1"},
		{"X-Real-IP": "10.0.0.1", "CF-IPCountry": "YY"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "203.0.113.9:1"
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("headers %v: %d, want 403 for a peer in a blocked country", hdr, w.Code)
		}
	}
}

// A request that reaches the bot guard through a trusted proxy is judged on the
// client address the proxy appended, so a forged loopback address earlier in
// the chain does not make a listed scanner "internal".
func TestBotGuardLoopbackExemptionNeedsARealLoopbackClient(t *testing.T) {
	chain := RealIP([]string{"10.0.0.0/8"})(BotGuard(logger.New("error", "text"), nil)(ok200()))
	for _, xff := range []string{"127.0.0.1, 198.51.100.7", "::1, 198.51.100.7", "localhost, 198.51.100.7"} {
		r := httptest.NewRequest("GET", "/wp-login.php", nil)
		r.RemoteAddr = "10.0.0.2:5000"
		r.Header.Set("X-Forwarded-For", xff)
		r.Header.Set("User-Agent", "sqlmap/1.7")
		w := httptest.NewRecorder()
		chain.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("X-Forwarded-For %q: %d, want 403 for a listed scanner", xff, w.Code)
		}
	}
}

// A WAF bypass prefix exempts what is served under it, decided on the path as
// the file handler resolves it (F2501). Re-checked with the spellings that
// resolve elsewhere: encoded and repeated dot segments, repeated slashes.
func TestDomainWAFBypassPrefixIsDecidedOnTheCanonicalPath(t *testing.T) {
	guard := DomainWAFGuard(logger.New("error", "text"), []string{"/wp-admin/"}, nil, nil)
	attack := "?q=1'+UNION+SELECT+password+FROM+users--"
	for _, tc := range []struct {
		path    string
		allowed bool
	}{
		{"/wp-admin/page.php", true}, // the exemption itself (control)
		{"/wp-admin/../x", false},
		{"/wp-admin/%2e%2e/x", false},
		{"/wp-admin/%2E%2E/x", false},
		{"/wp-admin/./../x", false},
		{"//wp-admin/../x", false},
		{"/./wp-admin/../x", false},
		{"/wp-admin/..//x", false},
		{"/wp-admin;/x", false},
		{"/wp-admin", false}, // no trailing slash: not under the prefix
		{"/wp-admin%2f../x", false},
	} {
		r := httptest.NewRequest("GET", tc.path+attack, nil)
		if got := guard(httptest.NewRecorder(), r); got != tc.allowed {
			t.Errorf("%s: allowed=%v, want %v", tc.path, got, tc.allowed)
		}
	}
}
