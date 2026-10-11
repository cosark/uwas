package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/auth"
)

// F10710: disabling the only enabled admin would lock everyone out of user
// management and login, so the update is refused; with another enabled admin,
// or for a non-admin, it is allowed.
func TestUserUpdateRefusesDisablingLastEnabledAdmin(t *testing.T) {
	s := testServer()
	mgr := newMockAuthManager()
	s.SetAuthManager(mgr)

	put := func(target, body string) int {
		req := withAdminContext(httptest.NewRequest("PUT", "/api/v1/auth/users/"+target, strings.NewReader(body)))
		req.SetPathValue("username", target)
		rec := httptest.NewRecorder()
		s.handleUserUpdateAuth(rec, req)
		return rec.Code
	}

	if c := put("admin", `{"enabled":false}`); c != http.StatusBadRequest {
		t.Errorf("disabling the last enabled admin: status %d, want 400", c)
	}
	if c := put("reseller", `{"enabled":false}`); c != http.StatusOK {
		t.Errorf("disabling a reseller: status %d, want 200", c)
	}
	if c := put("admin", `{"enabled":true}`); c != http.StatusOK {
		t.Errorf("enabling an admin: status %d, want 200", c)
	}

	if _, err := mgr.CreateUser("ops", "o@test.com", "x", auth.RoleAdmin, nil); err != nil {
		t.Fatal(err)
	}
	if c := put("admin", `{"enabled":false}`); c != http.StatusOK {
		t.Errorf("disabling an admin while another is enabled: status %d, want 200", c)
	}
}
