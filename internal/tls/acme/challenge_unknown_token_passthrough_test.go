package acme

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/uwaserver/uwas/internal/logger"
)

// F7601: an unknown token under /.well-known/acme-challenge/ must fall through
// to the site instead of being answered with a 404, so a tenant's own HTTP-01
// client (certbot webroot, a manual-cert domain) keeps working.
func TestHandleHTTPChallengeFallsThroughForUnknownToken(t *testing.T) {
	c := NewClient("http://127.0.0.1:1/dir", t.TempDir(), logger.New("error", "text"))
	c.httpTokens.Store("issued-token", "issued-token.thumb")

	for _, tc := range []struct {
		name        string
		path        string
		wantHandled bool
		wantBody    string
	}{
		{"issued token is served", "/.well-known/acme-challenge/issued-token", true, "issued-token.thumb"},
		{"unknown token falls through", "/.well-known/acme-challenge/tenant-own-token", false, ""},
		{"empty token falls through", "/.well-known/acme-challenge/", false, ""},
		{"ordinary path falls through", "/index.html", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://t.example"+tc.path, nil)
			if got := c.HandleHTTPChallenge(rec, req); got != tc.wantHandled {
				t.Fatalf("handled = %v, want %v", got, tc.wantHandled)
			}
			if rec.Body.String() != tc.wantBody {
				t.Errorf("body = %q, want %q", rec.Body.String(), tc.wantBody)
			}
		})
	}
}
