package admin

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// authmw decides which paths skip authentication (and which skip the 2FA gate)
// from the decoded r.URL.Path, while ServeMux routes on the escaped path one
// segment at a time. This pins that no encoding of a protected route's path
// slips under an exempt prefix or suffix: every such request stays refused
// (401), redirected to its cleaned form, or routed nowhere (404/405).
func TestExemptPathVariantsNeverReachAProtectedHandler(t *testing.T) {
	h := pinChain(t, "key-for-exempt-paths", "")
	// Each path decodes to something under an exempt prefix, or to an exempt
	// route, and resolves to a protected route once cleaned or unescaped.
	lures := []string{
		"/api/v1/auth/2fa/../users",
		"/api/v1/auth/2fa%2F..%2Fusers",
		"/api/v1/auth/2fa/../../domains",
		"/api/v1/auth/2fa/%2e%2e/users",
		"/_uwas/dashboard/../../api/v1/config/raw",
		"/_uwas/dashboard/%2e%2e/%2e%2e/api/v1/config/raw",
		"/_uwas/dashboard%2F..%2F..%2Fapi/v1/config/raw",
		"/_uwas/dashboardx/api/v1/config/raw",
		"/api/v1/settings/branding/../../config/raw",
		"/api/v1/health/../config/raw",
		"/api/v1/auth/login/../users",
		"/api/v1/auth/login%2F..%2Fusers",
		"//api/v1/config/raw",
		"/api/v1//config/raw",
		"/api/v1/%61uth/users",
		"/api/v1/auth/%75sers",
		"/api/v1/config/raw/",
		"/api/v1/config%2Fraw",
		"/api/v1/apps/x%2Fwebhook",
		"/api/v1/apps/../auth/users/webhook",
		"/api/v1/apps/x%2F..%2F..%2Fdomains%2Fwebhook",
		"/api/v1/apps/x/y/webhook",
	}
	n := 0
	for _, path := range lures {
		for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
			n++
			// A distinct client each time, so one lockout cannot mask the rest.
			remote := fmt.Sprintf("10.%d.%d.%d:40000", n/65536%256, n/256%256, n%256)
			code, body := peerDo(h, remote, method, path, `{}`, map[string]string{
				"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest",
			})
			// The dashboard's own static handler answers anything below its
			// prefix with the public single-page shell; that is not an admin
			// handler and needs no credentials.
			if code == http.StatusOK && strings.HasPrefix(path, "/_uwas/dashboard") &&
				strings.HasPrefix(strings.ToLower(strings.TrimSpace(body)), "<!doctype html") {
				continue
			}
			switch code {
			case http.StatusUnauthorized, http.StatusMovedPermanently, http.StatusPermanentRedirect,
				http.StatusTemporaryRedirect, http.StatusNotFound, http.StatusMethodNotAllowed:
			default:
				t.Errorf("%s %s = %d %.100s, want 401/redirect/404/405", method, path, code, body)
			}
		}
	}
}
