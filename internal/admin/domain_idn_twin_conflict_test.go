package admin

import (
	"net/http"
	"testing"

	"github.com/uwaserver/uwas/internal/auth"
	"github.com/uwaserver/uwas/internal/config"
)

// F13100: a host written in Unicode and its punycode spelling are one name on
// the wire. The conflict check compared them as different strings, so Add,
// Update and the raw editor accepted a second domain for a name another domain
// already owned: the router then served whichever registered last and the
// persisted config no longer loaded.
func TestDomainConflictChecksTreatIDNTwinsAsOne(t *testing.T) {
	const uni, puny = "bücher.example", "xn--bcher-kva.example"
	cases := []struct {
		name, method, path, body string
		role                     auth.Role
		domains                  []string
	}{
		{"admin add host twin", http.MethodPost, "/api/v1/domains", `{"host":"` + puny + `","type":"static","ssl":{"mode":"off"}}`, auth.RoleAdmin, nil},
		{"reseller add host twin", http.MethodPost, "/api/v1/domains", `{"host":"` + puny + `","type":"static","ssl":{"mode":"off"}}`, auth.RoleReseller, []string{puny}},
		{"add alias twin", http.MethodPost, "/api/v1/domains", `{"host":"newsite.com","type":"static","aliases":["` + puny + `"],"ssl":{"mode":"off"}}`, auth.RoleAdmin, nil},
		{"update alias twin", http.MethodPut, "/api/v1/domains/reseller.com", `{"aliases":["` + puny + `"]}`, auth.RoleAdmin, nil},
		{"rename to twin", http.MethodPut, "/api/v1/domains/reseller.com", `{"host":"` + puny + `"}`, auth.RoleAdmin, nil},
	}
	for _, c := range cases {
		e := newHostConflictEnv(t, []config.Domain{
			{Host: uni, Type: "static"},
			{Host: "reseller.com", Type: "static"},
		})
		if code := e.do(c.method, c.path, c.body, c.role, c.domains...); code != http.StatusConflict {
			t.Errorf("%s: status = %d, want 409", c.name, code)
		}
		if got := e.routeOf(puny); got != uni {
			t.Errorf("%s: %s routes to %q, want %s", c.name, puny, got, uni)
		}
		if _, err := config.Load(e.cfgPath); err != nil {
			t.Errorf("%s: persisted config no longer loads: %v", c.name, err)
		}
	}
}

// Control: an unrelated IDN host is not a conflict.
func TestDomainAddUnrelatedIDNHostIsAccepted(t *testing.T) {
	e := newHostConflictEnv(t, []config.Domain{{Host: "bücher.example", Type: "static"}})
	if code := e.do(http.MethodPost, "/api/v1/domains", `{"host":"xn--bcher-kva2.example","type":"static","ssl":{"mode":"off"}}`, auth.RoleAdmin); code == http.StatusConflict {
		t.Errorf("unrelated host refused as a conflict")
	}
}
