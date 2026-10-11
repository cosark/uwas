package admin

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/uwaserver/uwas/internal/auth"
	"github.com/uwaserver/uwas/internal/config"
)

// F12200: Add refuses a non-admin a hostname they are not assigned, but an
// alias is a hostname the site answers for (and is issued a certificate for)
// just as the host is. Add, Update and the raw editor must hold aliases to the
// same ownership: assigned hostnames and their subdomains, plus whatever the
// domain already carries.
func TestResellerAliasesNeedOwnership(t *testing.T) {
	newEnv := func(t *testing.T) *hostConflictEnv {
		return newHostConflictEnv(t, []config.Domain{{Host: "reseller.com", Type: "static"}})
	}
	update := func(e *hostConflictEnv, role auth.Role, body string, assigned ...string) int {
		return e.do(http.MethodPut, "/api/v1/domains/reseller.com", body, role, append([]string{"reseller.com"}, assigned...)...)
	}
	raw := func(e *hostConflictEnv, role auth.Role, aliases string) int {
		b, _ := json.Marshal(map[string]string{"content": "host: reseller.com\ntype: static\nroot: " + e.s.config.Domains[0].Root + "\nssl:\n  mode: \"off\"\n" + aliases})
		return e.do(http.MethodPut, "/api/v1/config/domains/reseller.com/raw", string(b), role, "reseller.com")
	}
	routed := func(e *hostConflictEnv, host string) bool { return e.routeOf(host) == host }

	t.Run("refused", func(t *testing.T) {
		e := newEnv(t)
		cases := []struct {
			name string
			do   func() int
		}{
			{"update", func() int { return update(e, auth.RoleReseller, `{"aliases":["customer-new.com"]}`) }},
			{"add", func() int {
				return e.do(http.MethodPost, "/api/v1/domains",
					`{"host":"mine.reseller.com","type":"static","aliases":["customer-two.com"],"ssl":{"mode":"off"}}`,
					auth.RoleReseller, "reseller.com", "mine.reseller.com")
			}},
			{"raw", func() int { return raw(e, auth.RoleReseller, "aliases:\n  - customer-three.com\n") }},
			{"www variant of an unassigned host", func() int { return update(e, auth.RoleReseller, `{"aliases":["www.customer-four.com"]}`) }},
			{"host that only ends like an assigned one", func() int { return update(e, auth.RoleReseller, `{"aliases":["evilreseller.com"]}`) }},
		}
		for _, c := range cases {
			if code := c.do(); code != http.StatusForbidden {
				t.Errorf("%s: status = %d, want 403", c.name, code)
			}
		}
		for _, h := range []string{"customer-new.com", "customer-two.com", "customer-three.com", "customer-four.com", "evilreseller.com"} {
			if routed(e, h) {
				t.Errorf("%s was attached by a refused request", h)
			}
		}
	})

	t.Run("allowed", func(t *testing.T) {
		e := newEnv(t)
		cases := []struct {
			name string
			do   func() int
		}{
			{"assigned hostname", func() int { return update(e, auth.RoleReseller, `{"aliases":["own-alias.com"]}`, "own-alias.com") }},
			{"subdomain of an assigned host", func() int { return update(e, auth.RoleReseller, `{"aliases":["blog.reseller.com"]}`) }},
			{"admin, any hostname", func() int { return update(e, auth.RoleAdmin, `{"aliases":["admin-set.com"]}`) }},
		}
		for _, c := range cases {
			if code := c.do(); code != http.StatusOK {
				t.Errorf("%s: status = %d, want 200", c.name, code)
			}
		}
		// What an admin attached stays editable: resubmitting it is not a new alias.
		if code := update(e, auth.RoleReseller, `{"aliases":["admin-set.com"],"cache":{"enabled":true}}`); code != http.StatusOK {
			t.Errorf("resubmitting an admin-set alias: status = %d, want 200", code)
		}
		if code := update(e, auth.RoleReseller, `{"cache":{"enabled":true}}`); code != http.StatusOK {
			t.Errorf("update without aliases: status = %d, want 200", code)
		}
	})
}
