package admin

// Characterization test (R127): which admin routes does a `user`-role (and, for
// comparison, a `reseller`-role) account get past authorization on?
//
// auth.rolePermissions gives RoleUser only domain:read and system:read, and
// UPGRADING.md calls the role read-only; but many handlers check only domain
// ownership (CanManageDomain). This test makes the difference visible. It
// asserts nothing about POLICY: it logs one SURFACE| line per route and fails
// only when the harness itself is broken (route table not parsed, or the
// baseline checks that prove the middleware chain is real do not hold).
//
// Safety: requests carry an empty `{}` body and a temp web root. Routes whose
// handlers could affect the host or reach the network (firewall, packages,
// services, software/database installs, ACME, DNS, backups, updates, terminal)
// are NOT executed under any identity; for those the test falls back to a
// static, heuristic scan of the handler for authorization calls. A static
// result is reliable only in its negative form ("no gate call found").

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/auth"
	"github.com/uwaserver/uwas/internal/config"
	"golang.org/x/crypto/bcrypt"
)

var surfaceHostAffecting = regexp.MustCompile(`(?i)(/auth/logout|/auth/login|/reload$|/restart$|/shutdown|/system/update|/update-check|/packages|/setup/|/firewall|/services/|/software|/database/(install|uninstall|force-uninstall|start|stop|restart|docker)|/cloudflare/|/dns/|/php/install|/php/\{version\}/(start|stop|restart)|/php/domains/\{domain\}/(start|stop)|/ssh-keys|/terminal|/backups|/renew|/acme|/metrics$|/_uwas/)`)

type surfaceRoute struct {
	method, pattern, handler string
}

type surfaceGates struct{ admin, perm, own bool }

func (g surfaceGates) String() string {
	var p []string
	if g.admin {
		p = append(p, "ADMIN")
	}
	if g.perm {
		p = append(p, "PERM")
	}
	if g.own {
		p = append(p, "OWN")
	}
	if len(p) == 0 {
		return "NONE"
	}
	return strings.Join(p, "+")
}

// surfaceFuncIndex parses every non-test Go file under the admin tree.
func surfaceFuncIndex(t *testing.T) map[string][]*ast.FuncDecl {
	t.Helper()
	idx := map[string][]*ast.FuncDecl{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		for _, decl := range f.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Body != nil {
				idx[fd.Name.Name] = append(idx[fd.Name.Name], fd)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk admin tree: %v", err)
	}
	return idx
}

func surfaceCalleeName(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// surfaceAnalyze reports authorization calls found in the named function and,
// to depth, in the functions it calls. Over-approximate by construction (it
// follows names, not types).
func surfaceAnalyze(idx map[string][]*ast.FuncDecl, name string, depth int, seen map[string]bool) surfaceGates {
	var g surfaceGates
	if seen[name] {
		return g
	}
	seen[name] = true
	for _, fd := range idx[name] {
		var callees []string
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				c := surfaceCalleeName(x)
				lc := strings.ToLower(c)
				switch {
				case lc == "requireadmin" || lc == "isadmin":
					g.admin = true
				case lc == "requirepermission":
					g.perm = true
				case lc == "canmanagedomain" || lc == "requiredomainaccess" || lc == "canaccessdomain":
					g.own = true
				}
				if c != "" {
					callees = append(callees, c)
				}
			case *ast.BinaryExpr:
				if x.Op == token.NEQ || x.Op == token.EQL {
					for _, side := range []ast.Expr{x.X, x.Y} {
						if sel, ok := side.(*ast.SelectorExpr); ok && sel.Sel.Name == "RoleAdmin" {
							g.admin = true
						}
					}
				}
			}
			return true
		})
		if depth > 0 {
			for _, c := range callees {
				if _, ok := idx[c]; ok {
					cg := surfaceAnalyze(idx, c, depth-1, seen)
					g.admin = g.admin || cg.admin
					g.perm = g.perm || cg.perm
					g.own = g.own || cg.own
				}
			}
		}
	}
	return g
}

func surfaceParseRoutes(t *testing.T) []surfaceRoute {
	t.Helper()
	src, err := os.ReadFile("routes.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`Handle(?:Func)?\("([A-Z]+) (/\S*)"(?:,\s*s\.(\w+)\))?`)
	var out []surfaceRoute
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		out = append(out, surfaceRoute{method: m[1], pattern: m[2], handler: m[3]})
	}
	return out
}

func surfaceFill(p string) string {
	return regexp.MustCompile(`\{([^}]+)\}`).ReplaceAllStringFunc(p, func(s string) string {
		switch strings.Trim(s, "{}.") {
		case "domain", "host", "hostname":
			return "victim.example"
		}
		return "x1"
	})
}

func surfaceClass(code int) string {
	switch {
	case code == 403:
		return "DENIED"
	case code == 401:
		return "UNAUTH401" // with a fresh valid session this means the chain rejected it; reported separately
	case code == 429:
		return "RATELIMITED"
	case code == -1:
		return "PANIC"
	case code == -2:
		return "HUNG"
	case code == -3:
		return "NO-SESSION"
	case code == 404:
		return "PAST?404" // handler-level not-found: authz verdict undetermined
	default:
		return "PAST"
	}
}

func TestUserRoleWriteSurface(t *testing.T) {
	dir := t.TempDir()
	webRoot := filepath.Join(dir, "www")
	victimRoot := filepath.Join(webRoot, "victim.example", "public_html")
	if err := os.MkdirAll(victimRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(victimRoot, "index.html"), []byte("hi"), 0o644)

	cfg := &config.Config{Global: config.GlobalConfig{WebRoot: webRoot, LogLevel: "info", LogFormat: "text"},
		Domains: []config.Domain{{Host: "victim.example", Type: "static", Root: victimRoot, SSL: config.SSLConfig{Mode: "off"}}}}
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

	for _, u := range []string{"roleuser", "rolesell"} {
		if _, aerr := mgr.Authenticate(u, "pw-correct-horse"); aerr != nil {
			t.Fatal(aerr)
		}
	}

	snapDomains := append([]config.Domain(nil), cfg.Domains...)
	snapGlobal := cfg.Global
	reset := func() {
		s.configMu.Lock()
		cfg.Domains = append([]config.Domain(nil), snapDomains...)
		cfg.Global = snapGlobal
		s.configMu.Unlock()
	}

	ctr := 0
	do := func(method, path, who string) (code int) {
		reset()
		defer func() {
			if r := recover(); r != nil {
				code = -1
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		req := httptest.NewRequest(method, "http://admin.local"+path, strings.NewReader(`{}`)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		ctr++
		req.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:5555", (ctr>>16)&255, (ctr>>8)&255, ctr&255)
		switch who {
		case "admin":
			req.Header.Set("Authorization", "Bearer adminkey-0123456789")
		case "":
		default:
			// Fresh session per request: a prior route (logout, password
			// change) may have invalidated the previous one, and a 401 caused by
			// that would be misread as an authorization denial.
			sess, aerr := mgr.Authenticate(who, "pw-correct-horse")
			if aerr != nil {
				return -3
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
	if len(routes) < 200 {
		t.Fatalf("parsed only %d routes from routes.go; the harness is broken", len(routes))
	}

	// Harness sanity: the chain is real (auth required, admin accepted).
	if c := do("GET", "/api/v1/system", ""); c != 401 {
		t.Fatalf("unauthenticated GET /api/v1/system = %d, want 401: the middleware chain is not what this test assumes", c)
	}
	if c := do("GET", "/api/v1/health", "admin"); c != 200 {
		t.Fatalf("admin GET /api/v1/health = %d, want 200", c)
	}

	type row struct {
		route          surfaceRoute
		executed       bool
		user, resel, a string
		userCode       int
		reselCode      int
		gates          surfaceGates
		ambiguousName  bool
	}
	var rows []row
	for _, r := range routes {
		if !strings.HasPrefix(r.pattern, "/api/v1/") {
			continue
		}
		rw := row{route: r}
		if r.handler != "" {
			rw.ambiguousName = len(idx[r.handler]) > 1
			rw.gates = surfaceAnalyze(idx, r.handler, 3, map[string]bool{})
		}
		if !surfaceHostAffecting.MatchString(r.pattern) {
			rw.executed = true
			p := surfaceFill(r.pattern)
			rw.userCode = do(r.method, p, "roleuser")
			rw.reselCode = do(r.method, p, "rolesell")
			rw.user = fmt.Sprintf("%s(%d)", surfaceClass(rw.userCode), rw.userCode)
			rw.resel = fmt.Sprintf("%s(%d)", surfaceClass(rw.reselCode), rw.reselCode)
			if surfaceClass(rw.userCode) != "DENIED" || surfaceClass(rw.reselCode) != "DENIED" {
				// Admin comparison only where a lower role got past authz.
				rw.a = fmt.Sprintf("%d", do(r.method, p, "admin"))
			} else {
				rw.a = "-"
			}
		}
		rows = append(rows, rw)
	}

	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].route.pattern != rows[j].route.pattern {
			return rows[i].route.pattern < rows[j].route.pattern
		}
		return rows[i].route.method < rows[j].route.method
	})

	// Per-route table.
	for _, rw := range rows {
		if !rw.executed {
			t.Logf("SURFACE|%-6s|%-62s|user=NOT-EXECUTED|resel=NOT-EXECUTED|admin=-|static=%s%s",
				rw.route.method, rw.route.pattern, rw.gates, map[bool]string{true: " (ambiguous handler name)", false: ""}[rw.ambiguousName])
			continue
		}
		t.Logf("SURFACE|%-6s|%-62s|user=%s|resel=%s|admin=%s|static=%s%s",
			rw.route.method, rw.route.pattern, rw.user, rw.resel, rw.a, rw.gates, map[bool]string{true: " (ambiguous handler name)", false: ""}[rw.ambiguousName])
	}

	// Summary. Counts are over the /api/v1/ routes parsed above.
	type tally struct{ total, executed, notExec, denied, past, past404, other int }
	count := func(pick func(row) (int, bool), nonGETOnly bool) tally {
		var tl tally
		for _, rw := range rows {
			if nonGETOnly && rw.route.method == "GET" {
				continue
			}
			tl.total++
			if !rw.executed {
				tl.notExec++
				continue
			}
			tl.executed++
			code, _ := pick(rw)
			switch surfaceClass(code) {
			case "DENIED":
				tl.denied++
			case "PAST":
				tl.past++
			case "PAST?404":
				tl.past404++
			default:
				tl.other++
			}
		}
		return tl
	}
	for _, nonGET := range []bool{false, true} {
		label := "all methods"
		if nonGET {
			label = "non-GET only"
		}
		u := count(func(r row) (int, bool) { return r.userCode, true }, nonGET)
		rs := count(func(r row) (int, bool) { return r.reselCode, true }, nonGET)
		t.Logf("SUMMARY|%s|routes=%d executed=%d not-executed(host-affecting)=%d", label, u.total, u.executed, u.notExec)
		t.Logf("SUMMARY|%s|USER     denied=%d past-authz=%d past-authz-404(undetermined)=%d other=%d", label, u.denied, u.past, u.past404, u.other)
		t.Logf("SUMMARY|%s|RESELLER denied=%d past-authz=%d past-authz-404(undetermined)=%d other=%d", label, rs.denied, rs.past, rs.past404, rs.other)
	}

	t.Logf("SUMMARY|USER non-GET routes where the handler was reached (not 401/403):")
	for _, rw := range rows {
		if rw.executed && rw.route.method != "GET" && surfaceClass(rw.userCode) != "DENIED" {
			t.Logf("SUMMARY|  USER  %-6s %-62s %s static=%s", rw.route.method, rw.route.pattern, rw.user, rw.gates)
		}
	}
	t.Logf("SUMMARY|NOT-EXECUTED non-GET routes whose handler shows NO admin or permission gate (static, heuristic; absence is the reliable signal):")
	for _, rw := range rows {
		if !rw.executed && rw.route.method != "GET" && !rw.gates.admin && !rw.gates.perm {
			t.Logf("SUMMARY|  STATIC-NO-ADMIN-NO-PERM %-6s %-62s static=%s", rw.route.method, rw.route.pattern, rw.gates)
		}
	}
	t.Logf("SUMMARY|EXECUTED non-GET routes where the USER got past authz and the handler shows neither a permission nor an admin gate:")
	for _, rw := range rows {
		if rw.executed && rw.route.method != "GET" && surfaceClass(rw.userCode) != "DENIED" && !rw.gates.admin && !rw.gates.perm {
			t.Logf("SUMMARY|  USER-PAST-NO-ADMIN-NO-PERM %-6s %-62s %s static=%s", rw.route.method, rw.route.pattern, rw.user, rw.gates)
		}
	}
	t.Logf("SUMMARY|routes where USER and RESELLER differ (non-GET):")
	for _, rw := range rows {
		if rw.executed && rw.route.method != "GET" && surfaceClass(rw.userCode) != surfaceClass(rw.reselCode) {
			t.Logf("SUMMARY|  DIFF %-6s %-62s user=%s resel=%s", rw.route.method, rw.route.pattern, rw.user, rw.resel)
		}
	}

	// The test must not mutate the host: the web root it used lives in t.TempDir().
	_ = http.StatusOK
}

// TestUserRoleFileWriteEffect records, without judging, whether a `user`-role
// session can create a file in its assigned domain's web root through the
// files API (the effect, not just the status code).
func TestUserRoleFileWriteEffect(t *testing.T) {
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
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw-correct-horse"), bcrypt.MinCost)
	adir := filepath.Join(dir, "auth")
	_ = os.MkdirAll(adir, 0o755)
	data, _ := json.Marshal([]*auth.User{{ID: "id-user", Username: "roleuser", Password: string(hash), Role: auth.RoleUser, Enabled: true, Domains: []string{"victim.example"}, CreatedAt: time.Now()}})
	_ = os.WriteFile(filepath.Join(adir, "users.json"), data, 0o600)
	mgr, err := auth.NewManager(adir, "adminkey-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Stop)
	s.SetAuthManager(mgr)
	h := s.authMiddleware(requireJSONMiddleware(s.mux.(*testMux).mux))
	sess, err := mgr.Authenticate("roleuser", "pw-correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body string) int {
		req := httptest.NewRequest(method, "http://admin.local"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		req.Header.Set("X-Session-Token", sess.Token)
		req.RemoteAddr = "10.9.9.9:1"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	// Baseline that proves the session is valid and the role is enforced somewhere.
	t.Logf("EFFECT|user GET /domains = %d", call("GET", "/api/v1/domains", ""))
	t.Logf("EFFECT|user PUT /domains/victim.example = %d", call("PUT", "/api/v1/domains/victim.example", `{}`))
	wc := call("PUT", "/api/v1/files/victim.example/write", `{"path":"probe.php","content":"<?php echo 1;"}`)
	_, serr := os.Stat(filepath.Join(root, "probe.php"))
	t.Logf("EFFECT|user PUT /files/victim.example/write = %d, file created=%v", wc, serr == nil)
	mc := call("POST", "/api/v1/files/victim.example/mkdir", `{"path":"newdir"}`)
	st, derr := os.Stat(filepath.Join(root, "newdir"))
	t.Logf("EFFECT|user POST /files/victim.example/mkdir = %d, dir created=%v", mc, derr == nil && st.IsDir())
}
