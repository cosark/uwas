package admin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/auth"
	"github.com/uwaserver/uwas/internal/config"
)

// F12800: the raw YAML editor validated the new domain on its own, so a host
// or alias another domain already owns was only caught when Reload failed. By
// then the conflicting file was on disk (and stayed there if the process died
// before the restore), and the caller saw 500 rather than 409.
func TestRawPutRefusesHostnameOwnedByAnotherDomainBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	webRoot := filepath.Join(dir, "www")
	for _, h := range []string{"victim.com", "reseller.com"} {
		if err := os.MkdirAll(filepath.Join(webRoot, h, "public_html"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfgPath := filepath.Join(dir, "uwas.yaml")
	write := func(p, s string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(cfgPath, "global:\n  web_root: "+webRoot+"\n  log_level: error\n")
	dom := func(host string, aliases string) string {
		return "host: " + host + "\ntype: static\nroot: " + filepath.Join(webRoot, host, "public_html") + "\nssl:\n  mode: \"off\"\n" + aliases
	}
	write(filepath.Join(dir, "domains.d", "victim.com.yaml"), dom("victim.com", "aliases: [shop.victim.com]\n"))
	resellerFile := filepath.Join(dir, "domains.d", "reseller.com.yaml")
	orig := dom("reseller.com", "")
	write(resellerFile, orig)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("setup load: %v", err)
	}
	s := testServerFromConfig(t, cfg)
	s.authMgr = newMockAuthManager()
	s.configPath = cfgPath
	seenAtReload := ""
	s.reloadFn = func() error {
		b, _ := os.ReadFile(resellerFile)
		seenAtReload = string(b)
		_, err := config.Load(cfgPath)
		return err
	}

	// Control: a non-conflicting edit goes through.
	put := func(content string) (int, string) {
		body := fmt.Sprintf(`{"content":%q}`, content)
		r := httptest.NewRequest(http.MethodPut, "/api/v1/config/domains/reseller.com/raw", strings.NewReader(body))
		r = r.WithContext(auth.WithUser(r.Context(), &auth.User{ID: "a", Username: "a", Role: auth.RoleAdmin, Enabled: true}))
		r.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, r)
		return rec.Code, rec.Body.String()
	}
	if code, body := put(dom("reseller.com", "aliases: [blog.reseller.com]\n")); code != http.StatusOK {
		t.Fatalf("control (no conflict) = %d %s", code, body)
	}
	write(resellerFile, orig)
	seenAtReload = ""

	code, body := put(dom("reseller.com", "aliases: [shop.victim.com]\n"))
	if code != http.StatusConflict {
		t.Errorf("status = %d, want 409: %s", code, strings.TrimSpace(body))
	}
	if strings.Contains(seenAtReload, "shop.victim.com") {
		t.Error("the conflicting domain file was written before the conflict was refused")
	}
	if b, _ := os.ReadFile(resellerFile); !strings.Contains(string(b), "reseller.com") || strings.Contains(string(b), "shop.victim.com") {
		t.Errorf("domain file changed: %q", b)
	}
	// A rename onto another domain's host is refused the same way.
	if code, body := put(dom("victim.com", "")); code != http.StatusConflict {
		t.Errorf("rename onto victim.com: status = %d, want 409: %s", code, strings.TrimSpace(body))
	}
}

// F12801: POST /unknown-domains/{host}/alias compared the host only with other
// domains' hosts, so a hostname another domain owns as an alias got a second
// owner that was persisted and that config.Load rejects on the next start.
func TestUnknownAliasRefusesHostnameOwnedAsAlias(t *testing.T) {
	e := newHostConflictEnv(t, []config.Domain{
		{Host: "victim.com", Type: "static", Aliases: []string{"shop.victim.com"}},
		{Host: "target.com", Type: "static"},
	})
	if code := e.do(http.MethodPost, "/api/v1/unknown-domains/free.example/alias", `{"domain":"target.com"}`, auth.RoleAdmin); code != http.StatusOK {
		t.Fatalf("control (free host) = %d", code)
	}
	if code := e.do(http.MethodPost, "/api/v1/unknown-domains/shop.victim.com/alias", `{"domain":"target.com"}`, auth.RoleAdmin); code != http.StatusConflict {
		t.Errorf("alias-owned host: status = %d, want 409", code)
	}
	if _, err := config.Load(e.cfgPath); err != nil {
		t.Errorf("persisted config no longer loads: %v", err)
	}
}
