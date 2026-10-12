package admin

// R128 fork C: gate table for the host-affecting routes that the R127
// characterization test deliberately did not execute. Static part: handler
// bodies are scanned for requireAdmin/RequirePermission/ownership calls.
// Dynamic part: a route is executed under reseller/user sessions only when its
// handler shows an admin gate (so the expected result is a 403 that touches
// nothing) or when it is a GET; every other route is listed NOT EXERCISED.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/auth"
	"github.com/uwaserver/uwas/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// Executed host-affecting routes that legitimately stay reachable for lower
// roles: public/static data, per-domain routes gated by ownership, and routes
// that answer 501 because their manager is absent in the test server (their
// handler bodies check ownership; see the R128 ledger).
var hostGateKnownOpen = map[string]bool{
	"GET /api/v1/cloudflare/ips":              true,
	"GET /api/v1/dns/{domain}":                true,
	"GET /api/v1/dns/{domain}/records":        true,
	"POST /api/v1/php/domains/{domain}/start": true,
	"POST /api/v1/php/domains/{domain}/stop":  true,
	"GET /api/v1/php/install-info":            true,
	"GET /api/v1/system/update-check":         true,
	"GET /api/v1/users/{domain}/ssh-keys":     true,
	"POST /api/v1/users/{domain}/ssh-keys":    true,
	"DELETE /api/v1/users/{domain}/ssh-keys":  true,
}

func TestHostRoutesAdminGate(t *testing.T) {
	dir := t.TempDir()
	webRoot := filepath.Join(dir, "www")
	root := filepath.Join(webRoot, "victim.example", "public_html")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Global: config.GlobalConfig{WebRoot: webRoot, LogLevel: "info", LogFormat: "text"},
		Domains: []config.Domain{{Host: "victim.example", Type: "static", Root: root, SSL: config.SSLConfig{Mode: "off"}}}}
	cfg.Global.Admin.APIKey = "adminkey-0123456789"
	cfg.Global.Users.Enabled = true
	s := testServerFromConfig(t, cfg)
	s.configPath = filepath.Join(dir, "uwas.yaml")

	hash, _ := bcrypt.GenerateFromPassword([]byte("pw-correct-horse"), bcrypt.MinCost)
	users := []*auth.User{
		{ID: "id-user", Username: "roleuser", Password: string(hash), Role: auth.RoleUser, Enabled: true, Domains: []string{"victim.example"}, CreatedAt: time.Now()},
		{ID: "id-resel", Username: "rolesell", Password: string(hash), Role: auth.RoleReseller, Enabled: true, Domains: []string{"victim.example"}, CreatedAt: time.Now()},
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
	do := func(method, path, who string) (code int) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		req := httptest.NewRequest(method, "http://admin.local"+path, strings.NewReader(`{}`)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		ctr++
		req.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:5555", (ctr>>16)&255, (ctr>>8)&255, ctr&255)
		sess, aerr := mgr.Authenticate(who, "pw-correct-horse")
		if aerr != nil {
			return -3
		}
		req.Header.Set("X-Session-Token", sess.Token)
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
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			return -2
		}
		return code
	}

	routes := surfaceParseRoutes(t)
	idx := surfaceFuncIndex(t)
	sort.SliceStable(routes, func(i, j int) bool {
		if routes[i].pattern != routes[j].pattern {
			return routes[i].pattern < routes[j].pattern
		}
		return routes[i].method < routes[j].method
	})
	var total, noAdmin, execd, notExec, lowPast int
	for _, r := range routes {
		if !strings.HasPrefix(r.pattern, "/api/v1/") || !surfaceHostAffecting.MatchString(r.pattern) {
			continue
		}
		total++
		g := surfaceGates{}
		if r.handler != "" {
			g = surfaceAnalyze(idx, r.handler, 3, map[string]bool{})
		}
		line := fmt.Sprintf("HOSTGATE|%-6s|%-58s|handler=%-28s|gate=%-10s|", r.method, r.pattern, r.handler, g)
		if !g.admin {
			noAdmin++
		}
		if r.handler == "" || (!g.admin && r.method != "GET") || strings.Contains(r.pattern, "/terminal") || strings.Contains(r.pattern, "/_uwas/") || strings.HasSuffix(r.pattern, "/metrics") || strings.Contains(r.pattern, "/auth/") {
			notExec++
			t.Logf("%sNOT EXERCISED", line)
			continue
		}
		execd++
		p := surfaceFill(r.pattern)
		uc, rc := do(r.method, p, "roleuser"), do(r.method, p, "rolesell")
		if uc != 403 || rc != 403 {
			lowPast++
			key := r.method + " " + r.pattern
			if !hostGateKnownOpen[key] {
				t.Errorf("%s: reseller=%d user=%d, want 403 (host-level route not admin gated)", key, rc, uc)
			}
		}
		t.Logf("%suser=%d resel=%d", line, uc, rc)
	}
	t.Logf("HOSTGATE-SUMMARY|host-affecting=%d no-admin-gate-static=%d executed=%d not-exercised=%d executed-with-nonDenied=%d", total, noAdmin, execd, notExec, lowPast)
}
