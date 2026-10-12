package admin

// R130 fork C: tenant isolation for routes whose domain comes from the request
// BODY (cron execute, php assign, wordpress install) and for per-role filtered
// list endpoints that need seeded per-tenant data (cron monitor, bandwidth,
// php domains, wordpress sites, domains, stats).

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/bandwidth"
	"github.com/uwaserver/uwas/internal/cronjob"
)

func q(s string) string { b, _ := json.Marshal(s); return string(b) }

func TestTenantBodyDomainRoutes(t *testing.T) {
	th, s, _ := newTenantHarness(t)
	strangers := []string{
		"b.example", "B.EXAMPLE", "b.example.", "alias-b.example", "b.example:8443",
		"bücher.example", "xn--bcher-kva.example", "BÜCHER.example", " b.example",
	}
	pm := s.phpMgr
	before := len(pm.GetDomainInstances())
	for _, who := range []string{"ua", "ra"} {
		for _, h := range strangers {
			// cron execute: command would run on the host if it got through.
			if _, code := th.req("POST", "/api/v1/cron/execute", who, `{"domain":`+q(h)+`,"command":"echo r130-must-not-run"}`); code != 403 {
				t.Errorf("cron/execute as %s domain=%q -> %d (want 403)", who, h, code)
			}
			// php assign
			if _, code := th.req("POST", "/api/v1/php/domains", who, `{"domain":`+q(h)+`,"version":"8.3"}`); code != 403 {
				t.Errorf("php/domains assign as %s domain=%q -> %d (want 403)", who, h, code)
			}
			// wordpress install; db_name makes a gate-passing request stop at 400
			// right after the access check, so nothing is downloaded.
			if _, code := th.req("POST", "/api/v1/wordpress/install", who, `{"domain":`+q(h)+`,"db_name":"x"}`); code != 403 {
				t.Errorf("wordpress/install as %s domain=%q -> %d (want 403)", who, h, code)
			}
		}
		// Control: owner passes the domain gate on wordpress/install (400 from the
		// db_name guard, not 403).
		if _, code := th.req("POST", "/api/v1/wordpress/install", who, `{"domain":"a.example","db_name":"x"}`); code != 400 {
			t.Errorf("control wordpress/install as %s owner -> %d (want 400)", who, code)
		}
	}
	if after := len(pm.GetDomainInstances()); after != before {
		t.Errorf("php assignments changed by a non-owner: %d -> %d", before, after)
	}
}

func TestTenantRoleFilteredLists(t *testing.T) {
	th, s, _ := newTenantHarness(t)

	mon := cronjob.NewMonitor(t.TempDir())
	mon.RecordExecution(cronjob.ExecutionRecord{ID: "1", Domain: "b.example", Command: "echo SECRET-B-CMD", Success: true, Output: "SECRET-B-OUT"})
	mon.RecordExecution(cronjob.ExecutionRecord{ID: "2", Domain: "a.example", Command: "echo OWN-A-CMD", Success: true})
	s.SetCronMonitor(mon)

	cfgDomains := s.config.Domains
	for i := range cfgDomains {
		cfgDomains[i].Bandwidth.Enabled = true
		cfgDomains[i].Bandwidth.DailyLimit = 1 << 30
		cfgDomains[i].Bandwidth.Action = "alert"
	}
	s.SetBandwidthManager(bandwidth.NewManager(cfgDomains))

	pm := s.phpMgr
	pm.RegisterExistingDomain("a.example", "8.3", "unix:/run/a.sock", "/tmp/a", nil)
	pm.RegisterExistingDomain("b.example", "8.3", "unix:/run/b.sock", "/tmp/b", nil)

	lists := []string{
		"/api/v1/cron/monitor", "/api/v1/bandwidth", "/api/v1/php/domains",
		"/api/v1/wordpress/sites", "/api/v1/domains", "/api/v1/stats/domains",
		"/api/v1/stats", "/api/v1/wordpress/install/status",
	}
	leak := []string{"b.example", "B.EXAMPLE", "SECRET-B", "bücher", "xn--bcher", "alias-b"}
	for _, who := range []string{"ua", "ra"} {
		for _, p := range lists {
			body, code := th.req("GET", p, who, "")
			if code == 403 || code == 404 || code == 501 {
				continue
			}
			for _, l := range leak {
				if strings.Contains(strings.ToLower(body), strings.ToLower(l)) {
					t.Errorf("LEAK %s as %s contains %q (status %d): %.200s", p, who, l, code, body)
				}
			}
		}
		// Controls: the owner's own row is visible where the endpoint filters.
		for _, p := range []string{"/api/v1/cron/monitor", "/api/v1/bandwidth", "/api/v1/php/domains"} {
			body, code := th.req("GET", p, who, "")
			if code != 200 || !strings.Contains(body, "a.example") {
				t.Errorf("control %s as %s: owner row missing (status %d): %.200s", p, who, code, body)
			}
		}
	}
	_ = url.PathEscape
}

// Every route with a non-domain path parameter ({name}, {db}, {id}, {username},
// {backup}, {key}...) names a host-level object (app, database, software
// instance, backup, user), not a tenant domain. A user or reseller must be
// refused before the handler looks the object up: the answer for a nonexistent
// object must be 403, never 404/400 from the handler body.
func TestNonDomainParamRoutesRefuseNonAdmin(t *testing.T) {
	th, _, _ := newTenantHarness(t)
	open := map[string]bool{
		// per-user self-service or ownership-gated inside the handler
		"GET /api/v1/auth/users/{username}":           true,
		"PUT /api/v1/auth/users/{username}":           true,
		"POST /api/v1/auth/users/{username}/password": true,
		"POST /api/v1/auth/users/{username}/apikey":   true,
		"DELETE /api/v1/auth/users/{username}":        true,
		// read-only host PHP facts open to every authenticated role (pending
		// decision with the owner, see the R130 ledger); the webhook is
		// authenticated by its HMAC secret, not by a session.
		"GET /api/v1/php/{version}/config":     true,
		"GET /api/v1/php/{version}/extensions": true,
		"POST /api/v1/apps/{name}/webhook":     true,
	}
	var n, exec int
	var notDenied []string
	for _, r := range surfaceParseRoutes(t) {
		if !strings.HasPrefix(r.pattern, "/api/v1/") || strings.Contains(r.pattern, "{domain}") || strings.Contains(r.pattern, "{host}") || !strings.Contains(r.pattern, "{") {
			continue
		}
		n++
		key := r.method + " " + r.pattern
		for _, who := range []string{"ua", "ra"} {
			exec++
			code := th.do(r.method, tenantFill(r.pattern, "x1"), who)
			if code != 403 && code != 401 && !open[key] {
				notDenied = append(notDenied, key+" as "+who+" -> "+strconv.Itoa(code))
			}
		}
	}
	t.Logf("NONDOMAIN-SUMMARY routes=%d requests=%d not-403=%d", n, exec, len(notDenied))
	for _, s := range notDenied {
		t.Error("NOT-403:", s)
	}
	if n < 60 {
		t.Fatalf("parsed only %d non-domain parameter routes, harness broken", n)
	}
}
