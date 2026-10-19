package migrate

import (
	"os/exec"
	"strings"
	"testing"
)

// runMigrateCapturingRsync runs Migrate with exec stubbed and returns the result
// plus the rsync source argument (empty when rsync never ran).
func runMigrateCapturingRsync(t *testing.T, sourcePath string) (*MigrateResult, string) {
	t.Helper()
	origCmd, origChown := execCommandFn, runChown
	defer func() { execCommandFn, runChown = origCmd, origChown }()
	runChown = func(string) error { return nil }
	var rsyncSrc string
	execCommandFn = func(name string, args ...string) *exec.Cmd {
		if name == "rsync" {
			for _, a := range args {
				if strings.HasPrefix(a, "u@h.example:") {
					rsyncSrc = a
				}
			}
		}
		return exec.Command("true")
	}
	res := Migrate(MigrateRequest{
		SourceHost: "u@h.example", SourcePort: "22", SourcePath: sourcePath,
		Domain: "a.test", LocalRoot: t.TempDir(),
	})
	return res, rsyncSrc
}

// An omitted source_path must be rejected: it would otherwise sync the remote
// filesystem root ("host:/") into the local web root with rsync --delete.
func TestMigrateRequiresSourcePath(t *testing.T) {
	res, src := runMigrateCapturingRsync(t, "")
	if res.Status != "error" || res.Error != "invalid source_path" {
		t.Fatalf("empty source_path: status=%q error=%q, want error/invalid source_path", res.Status, res.Error)
	}
	if src != "" {
		t.Fatalf("rsync ran against %q despite empty source_path", src)
	}

	// Control: an explicit path still syncs exactly that directory.
	res, src = runMigrateCapturingRsync(t, "/var/www/a")
	if res.Status != "done" || src != "u@h.example:/var/www/a/" {
		t.Fatalf("explicit path: status=%q rsync src=%q", res.Status, src)
	}
	// A relative path (relative to the remote home) remains valid.
	if _, src = runMigrateCapturingRsync(t, "www"); src != "u@h.example:www/" {
		t.Fatalf("relative path: rsync src=%q", src)
	}
	// Repeated call after a rejection behaves identically.
	if res, _ = runMigrateCapturingRsync(t, ""); res.Status != "error" {
		t.Fatalf("repeat empty source_path: status=%q", res.Status)
	}
}
