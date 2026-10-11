package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/auth"
	"github.com/uwaserver/uwas/internal/config"
)

// F12201: bulk import must run the validation Add runs. A row that fails it
// used to be appended and persisted, and the config then failed to load on the
// next start.
func TestBulkDomainImportRejectsInvalidRows(t *testing.T) {
	e := newHostConflictEnv(t, []config.Domain{{Host: "base.com", Type: "static"}})
	body := `{"domains":[
		{"host":"fine.com","type":"static"},
		{"host":"bad-type.com","type":"bogus"},
		{"host":"no-upstream.com","type":"proxy"},
		{"host":"no-cert.com","type":"static","ssl":"manual"},
		{"host":"bad host!.com","type":"static"},
		{"host":"outside.com","type":"static","root":"/etc"}
	]}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/domains/import", strings.NewReader(body))
	r = r.WithContext(auth.WithUser(r.Context(), &auth.User{ID: "a", Username: "a", Role: auth.RoleAdmin, Enabled: true}))
	rec := httptest.NewRecorder()
	e.s.mux.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Added   []string          `json:"added"`
		Skipped []string          `json:"skipped"`
		Invalid map[string]string `json:"invalid"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Added) != 1 || out.Added[0] != "fine.com" {
		t.Errorf("added = %v, want only fine.com", out.Added)
	}
	for _, h := range []string{"bad-type.com", "no-upstream.com", "no-cert.com", "bad host!.com", "outside.com"} {
		if out.Invalid[h] == "" {
			t.Errorf("%q: no rejection reason in %v", h, out.Invalid)
		}
		found := false
		for _, s := range out.Skipped {
			if s == h {
				found = true
			}
		}
		if !found {
			t.Errorf("%q missing from skipped %v", h, out.Skipped)
		}
	}
	if _, err := config.Load(e.cfgPath); err != nil {
		t.Fatalf("persisted config no longer loads: %v", err)
	}
	e.s.configMu.RLock()
	n := len(e.s.config.Domains)
	e.s.configMu.RUnlock()
	if n != 2 {
		t.Errorf("%d domains after import, want base.com + fine.com", n)
	}
}
