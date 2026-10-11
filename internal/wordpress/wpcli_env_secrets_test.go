package wordpress

import (
	"os/exec"
	"strings"
	"testing"
)

// F9210: wp-cli loads the site's plugins and themes in-process, so it must not
// be handed UWAS's own secrets.
func TestWPCLIEnvExcludesUWASSecrets(t *testing.T) {
	t.Setenv("UWAS_ADMIN_KEY", "SECRET-ADMIN-KEY")
	t.Setenv("CLOUDFLARE_API_TOKEN", "SECRET-CF")
	snap := saveHooks()
	t.Cleanup(func() { restoreHooks(snap) })
	execCommandFn = func(string, ...string) *exec.Cmd { return exec.Command("printenv") }
	out, err := wpCLI(t.TempDir(), "core", "version")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "PATH=") {
		t.Error("PATH missing from the wp-cli environment")
	}
	for _, leak := range []string{"SECRET-ADMIN-KEY", "SECRET-CF"} {
		if strings.Contains(out, leak) {
			t.Errorf("wp-cli environment leaked %q", leak)
		}
	}
}
