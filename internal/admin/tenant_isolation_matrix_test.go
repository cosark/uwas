package admin

// R129 fork C: cross-tenant isolation matrix for every {domain}/{host} route.
//
// R128 could not prove ownership checks on per-domain routes whose manager was
// absent in the test server (501/503 is returned before/after the gate with no
// way to tell). Here the DNS provider (testDNSProviderHook) and the PHP manager
// are present, so the handler reaches its ownership check. For a user and a
// reseller assigned to a.example only, every {domain}/{host} route is called
// for the OTHER tenant's host b.example spelled several ways (case, trailing
// dot, alias, Unicode/punycode twin) and must answer 403; the owner's own host
// in several spellings must be treated like the plain spelling (no wrongful
// denial, no bypass).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/auth"
	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/dnsmanager"
	"golang.org/x/crypto/bcrypt"
)

type fakeDNSProvider struct{ calls []string }

func (f *fakeDNSProvider) ListZones() ([]dnsmanager.Zone, error) { return nil, nil }
func (f *fakeDNSProvider) ListRecords(zoneID string) ([]dnsmanager.Record, error) {
	f.calls = append(f.calls, "list")
	return []dnsmanager.Record{{ID: "r1", Type: "TXT", Name: "b.example", Content: "SECRET-TXT"}}, nil
}
func (f *fakeDNSProvider) CreateRecord(zoneID string, rec dnsmanager.Record) (*dnsmanager.Record, error) {
	f.calls = append(f.calls, "create")
	return &rec, nil
}
func (f *fakeDNSProvider) UpdateRecord(zoneID, recordID string, rec dnsmanager.Record) (*dnsmanager.Record, error) {
	f.calls = append(f.calls, "update")
	return &rec, nil
}
func (f *fakeDNSProvider) DeleteRecord(zoneID, recordID string) error {
	f.calls = append(f.calls, "delete")
	return nil
}
func (f *fakeDNSProvider) FindZoneByDomain(domain string) (*dnsmanager.Zone, error) {
	return &dnsmanager.Zone{ID: "z1", Name: "example"}, nil
}

// routes with no ownership gate by design (documented in R128/R129 ledgers).
var tenantIsolationKnownOpen = map[string]bool{
	"GET /api/v1/dns/{domain}": true, // public DNS lookup (dnschecker), no tenant data
}

// Handlers that answer 404 "domain not found" instead of 403 on purpose, so a
// reseller cannot tell another tenant's host from a missing one.
var tenantIsolation404 = map[string]bool{
	"DELETE /api/v1/domains/{host}": true,
	"PUT /api/v1/domains/{host}":    true,
}

func tenantFill(p, host string) string {
	return regexp.MustCompile(`\{([^}]+)\}`).ReplaceAllStringFunc(p, func(s string) string {
		switch strings.Trim(s, "{}.") {
		case "domain", "host", "hostname":
			return url.PathEscape(host)
		}
		return "x1"
	})
}

type tenantHarness struct {
	do  func(method, path, who string) int
	get func(path, who string) (string, int)
}

func newTenantHarness(t *testing.T) (*tenantHarness, *Server, *fakeDNSProvider) {
	t.Helper()
	dir := t.TempDir()
	webRoot := filepath.Join(dir, "www")
	mk := func(h string) string {
		r := filepath.Join(webRoot, h, "public_html")
		if err := os.MkdirAll(r, 0o755); err != nil {
			t.Fatal(err)
		}
		return r
	}
	cfg := &config.Config{Global: config.GlobalConfig{WebRoot: webRoot, LogLevel: "info", LogFormat: "text"},
		Domains: []config.Domain{
			{Host: "a.example", Type: "static", Root: mk("a.example"), SSL: config.SSLConfig{Mode: "off"}},
			{Host: "b.example", Aliases: []string{"alias-b.example"}, Type: "static", Root: mk("b.example"), SSL: config.SSLConfig{Mode: "off"}},
			{Host: "bücher.example", Type: "static", Root: mk("xn--bcher-kva.example"), SSL: config.SSLConfig{Mode: "off"}},
		}}
	cfg.Global.Admin.APIKey = "adminkey-0123456789"
	cfg.Global.Users.Enabled = true
	s := testServerFromConfig(t, cfg)
	s.configPath = filepath.Join(dir, "uwas.yaml")
	s.SetPHPManager(testPHPManager())

	fake := &fakeDNSProvider{}
	orig := testDNSProviderHook
	testDNSProviderHook = func() dnsmanager.Provider { return fake }
	t.Cleanup(func() { testDNSProviderHook = orig })

	hash, _ := bcrypt.GenerateFromPassword([]byte("pw-correct-horse"), bcrypt.MinCost)
	mkU := func(id, name string, role auth.Role, doms ...string) *auth.User {
		return &auth.User{ID: id, Username: name, Password: string(hash), Role: role, Enabled: true, Domains: doms, CreatedAt: time.Now()}
	}
	users := []*auth.User{
		mkU("1", "ua", auth.RoleUser, "a.example"),
		mkU("2", "ra", auth.RoleReseller, "a.example"),
		mkU("3", "ui", auth.RoleUser, "bücher.example"),
		mkU("4", "ri", auth.RoleReseller, "xn--bcher-kva.example"),
	}
	adir := filepath.Join(dir, "auth")
	_ = os.MkdirAll(adir, 0o755)
	data, _ := json.Marshal(users)
	_ = os.WriteFile(filepath.Join(adir, "users.json"), data, 0o600)
	mgr, err := auth.NewManager(adir, "adminkey-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Stop)
	s.SetAuthManager(mgr)
	h := s.authMiddleware(requireJSONMiddleware(s.mux.(*testMux).mux))

	ctr := 0
	doBody := func(method, path, who string) (body string, code int) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		req := httptest.NewRequest(method, "http://admin.local"+path, strings.NewReader(`{}`)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		ctr++
		req.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:5555", (ctr>>16)&255, (ctr>>8)&255, ctr&255)
		if who == "admin" {
			req.Header.Set("Authorization", "Bearer adminkey-0123456789")
		} else {
			sess, aerr := mgr.Authenticate(who, "pw-correct-horse")
			if aerr != nil {
				return "", -3
			}
			req.Header.Set("X-Session-Token", sess.Token)
		}
		rec := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			defer func() {
				if r := recover(); r != nil {
					code = -1
				}
				close(done)
			}()
			h.ServeHTTP(rec, req)
			code = rec.Code
			body = rec.Body.String()
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			return "", -2
		}
		return body, code
	}
	do := func(method, path, who string) int { _, c := doBody(method, path, who); return c }
	return &tenantHarness{do: do, get: func(path, who string) (string, int) { return doBody("GET", path, who) }}, s, fake
}

func TestTenantIsolationMatrix(t *testing.T) {
	th, _, fake := newTenantHarness(t)

	// Another tenant's host b.example (and the IDN twin of bücher.example) in
	// every spelling a client can put in the path.
	strangerHosts := []string{
		"b.example", "B.EXAMPLE", "b.example.", "alias-b.example", "b.example:8443",
		"bücher.example", "xn--bcher-kva.example", "BÜCHER.example",
	}
	// The owner's own host.
	ownerSpell := []string{"a.example", "A.EXAMPLE", "a.example.", "a.example "}

	var routes []surfaceRoute
	for _, r := range surfaceParseRoutes(t) {
		if strings.HasPrefix(r.pattern, "/api/v1/") && (strings.Contains(r.pattern, "{domain}") || strings.Contains(r.pattern, "{host}")) {
			routes = append(routes, r)
		}
	}
	sort.SliceStable(routes, func(i, j int) bool {
		if routes[i].pattern != routes[j].pattern {
			return routes[i].pattern < routes[j].pattern
		}
		return routes[i].method < routes[j].method
	})
	if len(routes) < 45 {
		t.Fatalf("parsed only %d per-domain routes, harness broken", len(routes))
	}

	var exec, strangerPast, ownerDenied, parityBad int
	for _, r := range routes {
		key := r.method + " " + r.pattern
		for _, who := range []string{"ua", "ra"} {
			for _, h := range strangerHosts {
				before := len(fake.calls)
				code := th.do(r.method, tenantFill(r.pattern, h), who)
				exec++
				if len(fake.calls) != before {
					t.Errorf("DNS provider reached by non-owner %s: %s host=%q", who, key, h)
				}
				if code == 404 && tenantIsolation404[key] {
					// must be indistinguishable from a host that does not exist
					if miss := th.do(r.method, tenantFill(r.pattern, "nonexistent.example"), who); miss != 404 {
						t.Errorf("%s as %s: stranger host 404 but missing host %d (existence oracle)", key, who, miss)
					}
					continue
				}
				if code != 403 && !tenantIsolationKnownOpen[key] {
					strangerPast++
					t.Errorf("ISOLATION %s as %s host=%q -> %d (want 403)", key, who, h, code)
				}
			}
			base := th.do(r.method, tenantFill(r.pattern, "a.example"), who)
			exec++
			for _, h := range ownerSpell[1:] {
				code := th.do(r.method, tenantFill(r.pattern, h), who)
				exec++
				if (code == 403) != (base == 403) {
					parityBad++
					t.Errorf("PARITY %s as %s host=%q -> %d but a.example -> %d", key, who, h, code, base)
				}
			}
			if base == 403 {
				ownerDenied++
			}
		}
	}
	t.Logf("ISOLATION-SUMMARY routes=%d requests=%d stranger-not-403=%d parity-mismatch=%d owner-base-403(user/reseller x routes)=%d", len(routes), exec, strangerPast, parityBad, ownerDenied)
}

// IDN owner: an assignment written in one form must authorize the twin form.
func TestTenantIsolationIDNOwnerForms(t *testing.T) {
	th, _, _ := newTenantHarness(t)
	for _, who := range []string{"ui", "ri"} {
		base := th.do("GET", "/api/v1/bandwidth/"+url.PathEscape("bücher.example"), who)
		if base == 403 {
			t.Fatalf("%s: own host denied (%d)", who, base)
		}
		for _, h := range []string{"xn--bcher-kva.example", "BÜCHER.example", "bücher.example.", "XN--BCHER-KVA.EXAMPLE"} {
			if code := th.do("GET", "/api/v1/bandwidth/"+url.PathEscape(h), who); (code == 403) != (base == 403) {
				t.Errorf("%s host=%q -> %d, plain -> %d", who, h, code, base)
			}
		}
		for _, h := range []string{"a.example", "b.example", "bucher.example"} {
			if code := th.do("GET", "/api/v1/bandwidth/"+url.PathEscape(h), who); code != 403 {
				t.Errorf("%s host=%q -> %d, want 403", who, h, code)
			}
		}
	}
}

var _ = http.StatusOK

// Every parameterless GET under /api/v1 that a tenant can reach must not carry
// another tenant's host, root path or aliases in its body.
func TestTenantIsolationListsDoNotLeakOtherTenant(t *testing.T) {
	th, s, _ := newTenantHarness(t)
	s.configMu.Lock()
	for i := range s.config.Domains {
		if s.config.Domains[i].Host == "b.example" {
			s.config.Domains[i].Aliases = []string{"alias-b.example"}
			s.config.Domains[i].Proxy.Upstreams = []config.Upstream{{Address: "http://sentinelb-upstream.invalid:9000", Weight: 1}}
		}
	}
	s.configMu.Unlock()
	s.RecordAuditUser("domain.update", "b.example sentinelb", "127.0.0.1", "admin", true)

	sentinels := []string{"b.example", "sentinelb", "xn--bcher-kva", "bücher"}
	var routes []surfaceRoute
	for _, r := range surfaceParseRoutes(t) {
		if r.method == "GET" && strings.HasPrefix(r.pattern, "/api/v1/") && !strings.Contains(r.pattern, "{") &&
			!strings.Contains(r.pattern, "/sse/") && !strings.HasSuffix(r.pattern, "/terminal") && !strings.HasSuffix(r.pattern, "/metrics") {
			routes = append(routes, r)
		}
	}
	if len(routes) < 50 {
		t.Fatalf("parsed only %d list routes", len(routes))
	}
	_ = http.StatusOK
	// Control: the sentinels are really in the data the routes serve (the admin
	// sees them), so an absent sentinel for a tenant means scoping, not an empty
	// fixture.
	for _, p := range []string{"/api/v1/domains", "/api/v1/audit", "/api/v1/certs"} {
		body, code := th.get(p, "admin")
		if code != 200 || !strings.Contains(strings.ToLower(body), "b.example") {
			t.Fatalf("control: admin GET %s = %d without sentinel", p, code)
		}
	}
	leaks, execd := 0, 0
	for _, r := range routes {
		for _, who := range []string{"ua", "ra"} {
			body, code := th.get(r.pattern, who)
			execd++
			if code < 200 || code >= 300 {
				continue
			}
			low := strings.ToLower(body)
			for _, sen := range sentinels {
				if strings.Contains(low, strings.ToLower(sen)) {
					leaks++
					t.Errorf("LEAK GET %s as %s (%d) contains %q", r.pattern, who, code, sen)
				}
			}
		}
	}
	t.Logf("LIST-LEAK-SUMMARY routes=%d requests=%d leaks=%d", len(routes), execd, leaks)
}
