package mcp

import (
	"encoding/json"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
	"github.com/uwaserver/uwas/internal/metrics"
)

// TestDomainGetRedactsCredentialPHPOverrides pins that domain_get does not hand
// credential-bearing php.ini overrides to the MCP client. config_overrides
// accepts mysqli.default_pw and the like (phpmanager.INIOverrideAllowed only
// blocks sandbox directives), so the value is a database password exactly as
// php.env DB_PASSWORD is — and php.env is already cleared. The key stays
// visible so the agent can see the override is configured; ordinary directives
// are untouched; the live config must not be mutated.
func TestDomainGetRedactsCredentialPHPOverrides(t *testing.T) {
	cfg := &config.Config{
		Domains: []config.Domain{{
			Host: "ini.example.com",
			Type: "php",
			PHP: config.PHPConfig{
				ConfigOverrides: map[string]string{
					"mysqli.default_pw":   "canary-ini-db-password",
					"mysqli.default_user": "appuser",
					"memory_limit":        "256M",
				},
			},
		}},
	}
	s := New(cfg, logger.New("error", "text"), metrics.New())

	result, err := s.CallTool("domain_get", json.RawMessage(`{"host":"ini.example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	got := result.(config.Domain).PHP.ConfigOverrides

	t.Logf("EXPECTED: mysqli.default_pw = %q", redactedValue)
	t.Logf("ACTUAL:   mysqli.default_pw = %q", got["mysqli.default_pw"])
	if got["mysqli.default_pw"] != redactedValue {
		t.Errorf("credential php.ini override leaked: %q", got["mysqli.default_pw"])
	}
	// Controls: ordinary overrides stay readable.
	if got["memory_limit"] != "256M" {
		t.Errorf("memory_limit should remain: got %q", got["memory_limit"])
	}
	if got["mysqli.default_user"] != "appuser" {
		t.Errorf("mysqli.default_user should remain: got %q", got["mysqli.default_user"])
	}
	if cfg.Domains[0].PHP.ConfigOverrides["mysqli.default_pw"] != "canary-ini-db-password" {
		t.Error("live config ConfigOverrides was mutated by sanitization")
	}
}

func TestIsCredentialINIKey(t *testing.T) {
	for k, want := range map[string]bool{
		"mysqli.default_pw":          true,
		"mysql.default_password":     true,
		"pgsql.password":             true,
		"MYSQLI.DEFAULT_PW":          true,
		"session.save_handler":       false,
		"memory_limit":               false,
		"upload_max_filesize":        false,
		"opcache.memory_consumption": false,
		"mysqli.default_user":        false,
	} {
		if got := isCredentialINIKey(k); got != want {
			t.Errorf("isCredentialINIKey(%q) = %v, want %v", k, got, want)
		}
	}
}

func TestSanitizePHPOverridesEmpty(t *testing.T) {
	if got := sanitizePHPOverrides(nil); got != nil {
		t.Errorf("nil overrides = %v, want nil", got)
	}
}
