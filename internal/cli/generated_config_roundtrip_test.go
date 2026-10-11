package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

// The first-run and installer config must load through the real loader with no
// warning: a key the schema does not know is ignored without a word, so a
// generated file with a typo would silently run on defaults.
func TestGeneratedDefaultConfigLoadsWithoutWarnings(t *testing.T) {
	base := t.TempDir()
	cases := []struct {
		name                                  string
		httpPort, adminPort, adminBind, email string
	}{
		{"defaults", "80", "9443", "127.0.0.1", ""},
		{"public admin and ACME email", "8080", "9555", "0.0.0.0", "ops@example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := generateDefaultConfig(tc.httpPort, tc.adminPort, tc.adminBind, "k-0123456789abcdef", "123456",
				filepath.Join(base, "uwas"), filepath.Join(base, "www"), tc.email)
			p := filepath.Join(t.TempDir(), "uwas.yaml")
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(p)
			if err != nil {
				t.Fatalf("generated config does not load: %v\n%s", err, body)
			}
			for _, w := range cfg.Warnings {
				t.Errorf("generated config: loader warning: %s", w)
			}
			if got, want := cfg.Global.Admin.Listen, tc.adminBind+":"+tc.adminPort; got != want {
				t.Errorf("admin.listen = %q, want %q", got, want)
			}
		})
	}
}
