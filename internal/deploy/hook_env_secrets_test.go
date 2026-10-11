package deploy

import (
	"strings"
	"testing"
)

// F9210: deploy hooks and builds run tenant repo code; UWAS's own secrets must
// not reach them, while variables configured for the deploy still do.
func TestHookAndBuildEnvExcludeUWASSecrets(t *testing.T) {
	t.Setenv("UWAS_ADMIN_KEY", "SECRET-ADMIN-KEY")
	t.Setenv("CLOUDFLARE_API_TOKEN", "SECRET-CF")
	extra := map[string]string{"NPM_TOKEN": "explicit-token"}
	sh, err := runShellImpl(t.TempDir(), extra, "printenv")
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := runCmdImpl(t.TempDir(), extra, "printenv")
	if err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"runShell": sh, "runCmd": cmd} {
		if !strings.Contains(out, "PATH=") {
			t.Errorf("%s: PATH missing", name)
		}
		for _, leak := range []string{"SECRET-ADMIN-KEY", "SECRET-CF"} {
			if strings.Contains(out, leak) {
				t.Errorf("%s: environment leaked %q", name, leak)
			}
		}
		if !strings.Contains(out, "NPM_TOKEN=explicit-token") {
			t.Errorf("%s: explicitly configured variable dropped", name)
		}
	}
}
