package admin

import (
	"net/http"
	"testing"
)

// F16800: Update stores the domain it merged from the patch, so it must judge
// that whole domain. It ran ValidateDomainPartial on it, which skips the
// cross-field rules, so a PUT that set type proxy (no upstream) or type
// redirect (no target) was answered 200 and left a config the next start
// refused to load, which keeps the whole server from starting; a redirect to
// the cloud metadata endpoint was accepted although Add refuses it.
func TestUpdateJudgesTheMergedDomain(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		wantStatus int
	}{
		{"type proxy without upstreams", `{"type":"proxy"}`, http.StatusBadRequest},
		{"type redirect without a target", `{"type":"redirect"}`, http.StatusBadRequest},
		{"redirect to the metadata endpoint", `{"type":"redirect","redirect":{"target":"http://169.254.169.254/latest/","status":301}}`, http.StatusBadRequest},
		{"basic_auth enabled without users", `{"basic_auth":{"enabled":true}}`, http.StatusBadRequest},
		{"client_auth without a CA", `{"ssl":{"mode":"off","client_auth":"require"}}`, http.StatusBadRequest},

		// controls: valid updates keep working
		{"unrelated update", `{"cache":{"enabled":true,"ttl":60}}`, http.StatusOK},
		{"proxy with an upstream", `{"type":"proxy","proxy":{"upstreams":[{"address":"http://127.0.0.1:9000","weight":1}]}}`, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newParityEnv(t)
			code, body := e.call(parityAdmin, http.MethodPut, "/api/v1/domains/mine.com", tc.body)
			if code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", code, tc.wantStatus, body)
			}
			if err := e.loads(e.domains()); err != nil {
				t.Errorf("the configuration left behind does not load at the next start: %v", err)
			}
		})
	}
}
