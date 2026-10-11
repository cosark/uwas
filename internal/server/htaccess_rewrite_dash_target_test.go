package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

func htRewriteServer(t *testing.T, sites map[string]string) *Server {
	t.Helper()
	var doms []config.Domain
	for host, ht := range sites {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "page.txt"), []byte("PAGE-BODY"), 0o644)
		os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("OK-BODY"), 0o644)
		os.WriteFile(filepath.Join(dir, ".htaccess"), []byte(ht), 0o644)
		doms = append(doms, config.Domain{Host: host, Type: "static", Root: dir,
			SSL: config.SSLConfig{Mode: "off"}, Htaccess: config.HtaccessConfig{Mode: "import"}})
	}
	cfg := &config.Config{Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"}, Domains: doms}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	return s
}

func htRewriteGet(s *Server, host, path string) (int, string) {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = host
	req.RemoteAddr = "198.51.100.7:1"
	req.Header.Set("User-Agent", "uwas-test")
	rr := httptest.NewRecorder()
	s.handler.ServeHTTP(rr, req)
	b, _ := io.ReadAll(rr.Body)
	return rr.Code, string(b)
}

// F6400: a RewriteRule with target "-" and no [L] (WordPress ships
// `RewriteRule .* - [E=HTTP_AUTHORIZATION:...]` ahead of its front-controller
// rule) must not end the rule pass; the following rules still run.
func TestHtaccessDashRuleWithoutLastContinues(t *testing.T) {
	s := htRewriteServer(t, map[string]string{
		"ctl.test": "RewriteEngine On\nRewriteRule ^about$ page.txt [L]\n",
		"wp.test": "RewriteEngine On\nRewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]\n" +
			"RewriteBase /\nRewriteRule ^index\\.php$ - [L]\n" +
			"RewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . page.txt [L]\n",
		"skip.test": "RewriteEngine On\nRewriteRule ^s$ - [S=1]\nRewriteRule ^s$ ok.txt\nRewriteRule ^s$ - [F]\n",
	})
	for _, c := range []struct {
		host, path string
		code       int
		body       string
	}{
		{"ctl.test", "/about", 200, "PAGE-BODY"},
		{"wp.test", "/about", 200, "PAGE-BODY"},
		{"wp.test", "/ok.txt", 200, "OK-BODY"},
		{"skip.test", "/s", 403, ""}, // [S=1] skips the rewrite, the [F] rule after it still applies
	} {
		code, body := htRewriteGet(s, c.host, c.path)
		if code != c.code || (c.body != "" && body != c.body) {
			t.Errorf("%s%s: %d %.20q, want %d %q", c.host, c.path, code, body, c.code, c.body)
		}
	}
}

// F6401: a RewriteCond RE2 cannot compile (PCRE lookbehind) must not be
// dropped, or the rule fires for every request. An ordinary rule is skipped; an
// [F] guard fails the directory closed.
func TestHtaccessUncompilableConditionDoesNotWidenRule(t *testing.T) {
	s := htRewriteServer(t, map[string]string{
		"ctl.test":   "RewriteEngine On\nRewriteCond %{HTTP_USER_AGENT} ^NeverMatches\nRewriteRule ^ok\\.txt$ page.txt [L]\n",
		"lb.test":    "RewriteEngine On\nRewriteCond %{HTTP_USER_AGENT} (?<=NeverMatches)x\nRewriteRule ^ok\\.txt$ page.txt [L]\n",
		"guard.test": "RewriteEngine On\nRewriteCond %{HTTP_USER_AGENT} (?<=NeverMatches)x\nRewriteRule ^ok\\.txt$ - [F]\n",
	})
	if code, body := htRewriteGet(s, "ctl.test", "/ok.txt"); code != 200 || body != "OK-BODY" {
		t.Fatalf("control: %d %.20q", code, body)
	}
	if code, body := htRewriteGet(s, "lb.test", "/ok.txt"); code != 200 || body != "OK-BODY" {
		t.Errorf("uncompilable condition widened the rule: %d %.20q, want 200 OK-BODY", code, body)
	}
	if code, _ := htRewriteGet(s, "guard.test", "/ok.txt"); code != http.StatusInternalServerError {
		t.Errorf("guard rule with an uncompilable condition: %d, want fail-closed 500", code)
	}
}
