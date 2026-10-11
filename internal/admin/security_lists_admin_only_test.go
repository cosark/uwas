package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/autoblock"
	"github.com/uwaserver/uwas/internal/logger"
	"github.com/uwaserver/uwas/internal/middleware"
)

// F3200: GET /api/v1/security/blocked and GET /api/v1/autoblock list other
// tenants' visitor IPs/paths/UAs and must be admin-only.
func TestSecurityAndAutoblockListsAdminOnly(t *testing.T) {
	s := testServer()
	st := middleware.NewSecurityStats()
	st.Record("203.0.113.77", "/victim-tenant/secret", "waf", "ua-x")
	s.SetSecurityStats(st)
	ab := autoblock.New(autoblock.Config{Enabled: true}, logger.New("error", "text"))
	if err := ab.Block("198.51.100.23", "manual", 0); err != nil {
		t.Fatal(err)
	}
	s.SetAutoBlocker(ab)

	type ep struct {
		name, leak string
		h          func(http.ResponseWriter, *http.Request)
	}
	for _, e := range []ep{
		{"security/blocked", "203.0.113.77", s.handleSecurityBlocked},
		{"autoblock", "198.51.100.23", s.handleAutoBlockStatus},
	} {
		// control: admin sees it
		rec := httptest.NewRecorder()
		e.h(rec, withAdminContext(httptest.NewRequest("GET", "/x", nil)))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), e.leak) {
			t.Fatalf("control %s: admin code=%d body=%s", e.name, rec.Code, rec.Body)
		}
		for role, wrap := range map[string]func(*http.Request) *http.Request{"reseller": withResellerContext, "user": withUserContext} {
			rec := httptest.NewRecorder()
			e.h(rec, wrap(httptest.NewRequest("GET", "/x", nil)))
			if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), e.leak) {
				t.Errorf("EXPECTED: %s %s → 403 without foreign IP\nACTUAL: code=%d leaked=%v", e.name, role, rec.Code, strings.Contains(rec.Body.String(), e.leak))
			}
		}
	}
}
