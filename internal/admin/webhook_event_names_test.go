package admin

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// F13802: a webhook subscribed to an event nothing fires under is dead on
// arrival, and config validation refuses to load it, so the admin API must not
// persist one.
func TestWebhookEventNamesAreValidatedBeforeSaving(t *testing.T) {
	s := testServer()
	for _, tc := range []struct {
		name, method, path, body string
		want                     int
	}{
		{"create ok", "POST", "/api/v1/webhooks", `{"url":"https://example.com/hook","events":["login.failed"]}`, 0},
		{"create typo", "POST", "/api/v1/webhooks", `{"url":"https://example.com/hook","events":["login_failed"]}`, 400},
		{"create case", "POST", "/api/v1/webhooks", `{"url":"https://example.com/hook","events":["Domain.Add"]}`, 400},
		{"prefs ok", "PUT", "/api/v1/settings/notifications", `{"webhooks":[{"url":"https://example.com/hook","events":["cert.expiry"]}]}`, 0},
		{"prefs typo", "PUT", "/api/v1/settings/notifications", `{"webhooks":[{"url":"https://example.com/hook","events":["cert_expiry"]}]}`, 400},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		s.mux.ServeHTTP(rec, withAdminContext(req))
		if tc.want == 0 {
			if rec.Code >= 400 {
				t.Errorf("%s: status %d (%s), want success", tc.name, rec.Code, rec.Body.String())
			}
			continue
		}
		if rec.Code != tc.want || !strings.Contains(rec.Body.String(), "unknown webhook event") {
			t.Errorf("%s: status %d body %q, want %d naming the event", tc.name, rec.Code, rec.Body.String(), tc.want)
		}
	}
}
