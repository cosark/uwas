package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/siteuser"
)

const minimalValidConfig = `domains:
  - host: test.com
    root: /tmp
    type: static
    ssl:
      mode: "off"
`

// F14300: "uwas serve" finds its config through findConfig (./uwas.yaml,
// ./.uwas/uwas.yaml, ~/.uwas, /etc/uwas). "uwas config validate" defaulted to
// the literal path uwas.yaml, so it reported "invalid: ... no such file" for a
// config the server starts with, and validated nothing.
func TestConfigValidateFindsConfigLikeServe(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".uwas"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".uwas", "uwas.yaml"), []byte(minimalValidConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	for _, sub := range []string{"validate", "test"} {
		var err error
		captureStdout(t, func() { err = (&ConfigCommand{}).Run([]string{sub}) })
		if err != nil {
			t.Errorf("config %s without -c: %v (serve would start with .uwas/uwas.yaml)", sub, err)
		}
	}
}

// An explicit -c still names exactly that file.
func TestConfigValidateExplicitPathStillWins(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "uwas.yaml"), []byte(minimalValidConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	err := (&ConfigCommand{}).Run([]string{"validate", "-c", filepath.Join(dir, "missing.yaml")})
	if err == nil {
		t.Fatal("validate -c <missing file> succeeded; it must not fall back to ./uwas.yaml")
	}
}

// F14300: the loader reports keys it ignores in Config.Warnings and the server
// logs them. "config validate" is where an operator looks for a typo, and it
// said "valid" without a word about it.
func TestConfigValidateReportsLoaderWarnings(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "uwas.yaml")
	body := minimalValidConfig + "securty:\n  waf:\n    enabled: true\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"validate", "test"} {
		var err error
		var out string
		stderr := captureStderr(t, func() {
			out = captureStdout(t, func() { err = (&ConfigCommand{}).Run([]string{sub, "-c", cfg}) })
		})
		if err != nil {
			t.Fatalf("config %s: %v", sub, err)
		}
		if !strings.Contains(stderr+out, "securty") {
			t.Errorf("config %s did not mention the ignored key securty\nstdout: %s\nstderr: %s", sub, out, stderr)
		}
	}
}

// F14301: "uwas user add <domain>" created the account under
// <web_root>/<domain-as-typed>/public_html whatever the domain's configured
// root is. The admin API resolves the configured domain and uses its root, so
// the CLI built an SFTP chroot onto a directory the site does not serve (and
// under a different name for another spelling of the host).
func TestUserAddUsesTheConfiguredDomainRoot(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "uwas.yaml")
	body := "global:\n  web_root: /var/www\ndomains:\n  - host: shop.example\n    root: /srv/sites/shop/www\n    type: static\n    ssl:\n      mode: \"off\"\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	origFind, origGOOS, origEUID := findConfigFn, userRuntimeGOOS, userOsGeteuid
	origCreate, origCreateDir := userCreateUserFn, userCreateUserForWebDirFn
	t.Cleanup(func() {
		findConfigFn, userRuntimeGOOS, userOsGeteuid = origFind, origGOOS, origEUID
		userCreateUserFn, userCreateUserForWebDirFn = origCreate, origCreateDir
	})
	findConfigFn = func(string) (string, bool) { return cfg, true }
	userRuntimeGOOS = "linux"
	userOsGeteuid = func() int { return 0 }

	var gotWebDir, gotIdentity string
	userCreateUserFn = func(webRoot, host string) (*siteuser.User, string, error) {
		gotWebDir, gotIdentity = filepath.Join(webRoot, host, "public_html"), host
		return &siteuser.User{Domain: host, Username: "u", WebDir: gotWebDir}, "pw", nil
	}
	userCreateUserForWebDirFn = func(webDir, host string) (*siteuser.User, string, error) {
		gotWebDir, gotIdentity = webDir, host
		return &siteuser.User{Domain: host, Username: "u", WebDir: webDir}, "pw", nil
	}

	for _, typed := range []string{"shop.example", "Shop.Example", "shop.example."} {
		gotWebDir, gotIdentity = "", ""
		var err error
		captureStdout(t, func() { err = (&UserCommand{}).Run([]string{"add", typed}) })
		if err != nil {
			t.Fatalf("user add %q: %v", typed, err)
		}
		if gotWebDir != "/srv/sites/shop/www" {
			t.Errorf("user add %q: web dir %q, want the configured root /srv/sites/shop/www", typed, gotWebDir)
		}
		if gotIdentity != "shop.example" {
			t.Errorf("user add %q: identity %q, want the configured host shop.example", typed, gotIdentity)
		}
	}

	// A host with no configured domain keeps the <web_root>/<host>/public_html layout.
	gotWebDir, gotIdentity = "", ""
	var err error
	captureStdout(t, func() { err = (&UserCommand{}).Run([]string{"add", "unlisted.example"}) })
	if err != nil {
		t.Fatalf("user add unlisted.example: %v", err)
	}
	if gotWebDir != "/var/www/unlisted.example/public_html" {
		t.Errorf("unconfigured host: web dir %q, want /var/www/unlisted.example/public_html", gotWebDir)
	}
}

// F14302: stop/restart/status locate the pid file and the admin API from the
// config, reading the raw file. The server expands ${VAR} and ${VAR:-fallback}
// and drops a UTF-8 BOM before it parses; the CLI did neither, so a systemd
// style pid_file: ${RUNTIME_DIRECTORY}/uwas.pid was looked up literally.
func TestQuickConfigValueExpandsEnvLikeTheLoader(t *testing.T) {
	t.Setenv("UWAS_T_RUN", "/run/uwas-t")
	os.Unsetenv("UWAS_T_ADMIN")

	orig := findConfigFn
	t.Cleanup(func() { findConfigFn = orig })
	use := func(body string) {
		p := filepath.Join(t.TempDir(), "uwas.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		findConfigFn = func(string) (string, bool) { return p, true }
	}

	use("global:\n  pid_file: ${UWAS_T_RUN}/uwas.pid\n  admin:\n    listen: \"${UWAS_T_ADMIN:-127.0.0.1:9777}\"\n")
	if got := pidFileFromConfig(); got != "/run/uwas-t/uwas.pid" {
		t.Errorf("pid_file = %q, want /run/uwas-t/uwas.pid", got)
	}
	if got := adminURLFromConfig(); got != "http://127.0.0.1:9777" {
		t.Errorf("admin URL = %q, want http://127.0.0.1:9777", got)
	}

	// Control: a UTF-8 BOM (Windows editors add one; the loader strips it) must
	// not push the reader onto its line-scan fallback, which finds mcp.listen
	// first. yaml.v3 accepts the BOM, so this held before F14302 as well.
	use("\xEF\xBB\xBFglobal:\n  mcp:\n    listen: \"127.0.0.1:9000\"\n  admin:\n    listen: \"127.0.0.1:9555\"\n")
	if got := adminURLFromConfig(); got != "http://127.0.0.1:9555" {
		t.Errorf("admin URL with BOM = %q, want http://127.0.0.1:9555", got)
	}
}
