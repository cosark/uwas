package admin

import (
	"net/http"
	"testing"

	"github.com/uwaserver/uwas/internal/auth"
	"github.com/uwaserver/uwas/internal/config"
)

// F13701: PUT /api/v1/domains/{host} decoded the body with json.Unmarshal, which
// drops fields the struct does not have. A misspelled security field
// ("securtiy", "security.blocked_path", a made-up "waf_enabled") was answered
// 200 while nothing changed, so the operator believed the protection was on.
func TestDomainUpdateRejectsUnknownFields(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"control: real field is applied", `{"security":{"blocked_paths":["/private"]}}`, http.StatusOK},
		{"control: alias options are not domain fields", `{"alias_mode":"redirect","alias_redirect_code":301,"alias_preserve_path":true}`, http.StatusOK},
		{"control: canonical_host", `{"canonical_host":"apex"}`, http.StatusOK},
		{"control: keys match case-insensitively like encoding/json", `{"Security":{"Blocked_Paths":["/p2"]}}`, http.StatusOK},
		{"misspelled top-level key", `{"securtiy":{"blocked_paths":["/private"]}}`, http.StatusBadRequest},
		{"invented top-level key", `{"waf_enabled":true}`, http.StatusBadRequest},
		{"misspelled nested key", `{"security":{"blocked_path":["/private"]}}`, http.StatusBadRequest},
		{"misspelled deeper key", `{"security":{"waf":{"enable":true}}}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newHostConflictEnv(t, []config.Domain{{Host: "a.com", Type: "static"}})
			code := e.do(http.MethodPut, "/api/v1/domains/a.com", c.body, auth.RoleAdmin)
			if code != c.want {
				t.Fatalf("status = %d, want %d", code, c.want)
			}
			e.s.configMu.RLock()
			defer e.s.configMu.RUnlock()
			applied := len(e.s.config.Domains[0].Security.BlockedPaths) > 0
			if c.want == http.StatusBadRequest && applied {
				t.Errorf("a rejected request changed the domain: %+v", e.s.config.Domains[0].Security)
			}
		})
	}
}

// Create goes through the same decoder: a misspelled field on POST /domains was
// accepted and the domain was created without the setting.
func TestDomainAddRejectsUnknownFields(t *testing.T) {
	add := func(t *testing.T, body string) int {
		t.Helper()
		e := newHostConflictEnv(t, []config.Domain{{Host: "other.com", Type: "static"}})
		return e.do(http.MethodPost, "/api/v1/domains", body, auth.RoleAdmin)
	}
	if code := add(t, `{"host":"new.com","type":"static","security":{"blocked_paths":["/p"]}}`); code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("control: status = %d, want 200/201", code)
	}
	if code := add(t, `{"host":"new.com","type":"static","securtiy":{"blocked_paths":["/p"]}}`); code != http.StatusBadRequest {
		t.Errorf("misspelled top-level key: status = %d, want 400", code)
	}
	if code := add(t, `{"host":"new.com","type":"static","security":{"blocked_path":["/p"]}}`); code != http.StatusBadRequest {
		t.Errorf("misspelled nested key: status = %d, want 400", code)
	}
}
