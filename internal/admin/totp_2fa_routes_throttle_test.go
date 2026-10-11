package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// F8000: /api/v1/auth/2fa/* is exempt from the middleware's TOTP gate, so a
// wrong code on those routes must itself count as an auth failure; otherwise
// a first-factor credential can grind through the 6-digit code space (and the
// recovery-code route) without ever being throttled.
func TestTwoFARoutesThrottleWrongCodes(t *testing.T) {
	s := testServer()
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	s.config.Global.Admin.APIKey = "k-0123456789abcdef0123456789abcdef"
	s.config.Global.Admin.TOTPSecret = secret

	bad := "000000"
	for off := int64(-1); off <= 1; off++ {
		if totpActivationCode(t, secret, off) == bad {
			bad = "000001"
		}
	}

	h := s.authMiddleware(s.mux)
	post := func(ip, path, body string, hdr map[string]string) int {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.RemoteAddr = ip + ":4000"
		req.Header.Set("Authorization", "Bearer "+s.config.Global.Admin.APIKey)
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	cases := []struct {
		name, path, body string
		hdr              map[string]string
	}{
		{"disable", "/api/v1/auth/2fa/disable", `{"code":"` + bad + `"}`, nil},
		{"verify", "/api/v1/auth/2fa/verify", `{"code":"` + bad + `"}`, nil},
		{"recovery-codes step-up", "/api/v1/auth/2fa/recovery-codes", `{}`, map[string]string{"X-TOTP-Code": bad}},
		{"recover", "/api/v1/auth/2fa/recover", `{"code":"0000000000000000"}`, nil},
	}
	for i, c := range cases {
		ip := "203.0.113." + string(rune('1'+i))
		throttled := false
		for n := 0; n < 30 && !throttled; n++ {
			throttled = post(ip, c.path, c.body, c.hdr) == http.StatusTooManyRequests
		}
		if !throttled {
			t.Errorf("%s: 30 wrong codes were never throttled", c.name)
		}
		// Control: another client is unaffected.
		if code := post("198.51.100."+string(rune('1'+i)), "/api/v1/auth/2fa/status", "", nil); code == http.StatusTooManyRequests {
			t.Errorf("%s: unrelated client was throttled", c.name)
		}
	}
}
