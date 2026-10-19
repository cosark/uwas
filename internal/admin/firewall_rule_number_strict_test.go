package admin

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFirewallRuleNumberRejectsTrailingJunk pins the {number} path value of the
// firewall delete and move routes: it must be a plain integer. fmt.Sscanf("%d")
// stops at the first non-digit and reports success, so "3abc", "1e2" and "3.5"
// were read as rule 3, 1 and 3 and the handler deleted or moved a rule the
// operator never named.
func TestFirewallRuleNumberRejectsTrailingJunk(t *testing.T) {
	origDelete, origMove := firewallDeleteRule, firewallMoveRule
	defer func() { firewallDeleteRule, firewallMoveRule = origDelete, origMove }()

	var deleted, moved []int
	firewallDeleteRule = func(n int) error { deleted = append(deleted, n); return nil }
	firewallMoveRule = func(n int, dir string) error { moved = append(moved, n); return nil }

	s := testServer()

	for _, bad := range []string{"3abc", "1e2", "3.5", "7 "} {
		deleted, moved = nil, nil

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("DELETE", "/api/v1/firewall/rules/x", nil)
		req.SetPathValue("number", bad)
		s.handleFirewallDelete(rec, withAdminContext(req))
		if rec.Code != 400 || len(deleted) != 0 {
			t.Errorf("delete %q: status=%d deleted=%v, want 400 and no delete", bad, rec.Code, deleted)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest("POST", "/api/v1/firewall/rules/x/move", strings.NewReader(`{"direction":"up"}`))
		req.SetPathValue("number", bad)
		s.handleFirewallMove(rec, withAdminContext(req))
		if rec.Code != 400 || len(moved) != 0 {
			t.Errorf("move %q: status=%d moved=%v, want 400 and no move", bad, rec.Code, moved)
		}
	}

	// Control: a plain number still reaches the firewall.
	deleted, moved = nil, nil
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/v1/firewall/rules/3", nil)
	req.SetPathValue("number", "3")
	s.handleFirewallDelete(rec, withAdminContext(req))
	if rec.Code != 200 || len(deleted) != 1 || deleted[0] != 3 {
		t.Errorf("delete 3: status=%d deleted=%v, want 200 and [3]", rec.Code, deleted)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/v1/firewall/rules/4/move", strings.NewReader(`{"direction":"up"}`))
	req.SetPathValue("number", "4")
	s.handleFirewallMove(rec, withAdminContext(req))
	if rec.Code != 200 || len(moved) != 1 || moved[0] != 4 {
		t.Errorf("move 4: status=%d moved=%v, want 200 and [4]", rec.Code, moved)
	}
}
