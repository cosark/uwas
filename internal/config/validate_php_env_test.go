package config

import (
	"os"
	"path/filepath"
	"testing"
)

// F12000: the php.env guard is a function callers can run on its own, because
// the loader (and the raw YAML editor, which validates with it) deliberately
// accepts an operator-written PHP_ADMIN_VALUE (UPGRADING.md, "explicit,
// reviewed PHP_ADMIN_VALUE") while the admin JSON API never does.
func TestValidatePHPEnv(t *testing.T) {
	bad := []string{"PHP_ADMIN_VALUE", "PHP_VALUE", "PHP_INI_SCAN_DIR"}
	for _, k := range bad {
		d := &Domain{PHP: PHPConfig{Env: map[string]string{k: "x"}}}
		if err := ValidatePHPEnv(d); err == nil {
			t.Errorf("php.env %s accepted", k)
		}
		if err := ValidateDomain(&Domain{Host: "a.com", Type: "php", PHP: d.PHP}); err == nil {
			t.Errorf("ValidateDomain accepted php.env %s", k)
		}
	}
	for _, k := range []string{"APP_ENV", "PHP_AUTH_USER", "TZ"} {
		d := &Domain{PHP: PHPConfig{Env: map[string]string{k: "x"}}}
		if err := ValidatePHPEnv(d); err != nil {
			t.Errorf("php.env %s rejected: %v", k, err)
		}
	}
	if err := ValidatePHPEnv(nil); err != nil {
		t.Errorf("nil domain: %v", err)
	}
}

// The loader keeps accepting an operator's own PHP_ADMIN_VALUE: it is the
// documented way to widen open_basedir, and the runtime filter drops the
// directives that weaken the sandbox.
func TestLoadAcceptsOperatorPHPAdminValue(t *testing.T) {
	dir := t.TempDir()
	root := t.TempDir()
	yml := "global:\n  web_root: " + dir + "\ndomains:\n  - host: example.com\n    type: php\n    root: " + root +
		"\n    ssl: {mode: \"off\"}\n    php:\n      env:\n        PHP_ADMIN_VALUE: \"memory_limit=256M\"\n"
	if err := os.WriteFile(filepath.Join(dir, "uwas.yaml"), []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(dir, "uwas.yaml")); err != nil {
		t.Fatalf("Load rejected an operator PHP_ADMIN_VALUE: %v", err)
	}
}
