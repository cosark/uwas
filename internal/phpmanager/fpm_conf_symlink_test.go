//go:build unix

package phpmanager

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// startFPMIn drives the real startFPMDaemon with the shared temp dir pointed
// at tmp, so the predictable <tmp>/uwas-fpm location can be pre-seeded.
func startFPMIn(t *testing.T, tmp string) error {
	t.Helper()
	origUser := fpmPoolUser
	t.Cleanup(func() { fpmPoolUser = origUser })
	fpmPoolUser = func() (string, bool) { return "www-data", true }
	t.Setenv("TMPDIR", tmp)
	m := New(testLogger())
	m.execCommand = func(name string, args ...string) *exec.Cmd { return exec.Command("sleep", "100") }
	t.Cleanup(func() {
		if val, ok := m.processes.Load("8.4.19"); ok {
			if info, ok := val.(*processInfo); ok && info.cmd != nil && info.cmd.Process != nil {
				_ = info.cmd.Process.Kill()
			}
			m.processes.Delete("8.4.19")
		}
	})
	return m.startFPMDaemon("8.4.19", "/usr/sbin/php-fpm8.4", "127.0.0.1:9000")
}

// The pool config is written under a predictable path in the shared temp dir
// while the daemon is started as root; a symlink planted at that path used to
// redirect the write onto any file (F8210).
func TestStartFPMDaemonDoesNotFollowPlantedConfigSymlink(t *testing.T) {
	d := t.TempDir()
	victim := filepath.Join(d, "victim.txt")
	if err := os.WriteFile(victim, []byte("PRECIOUS"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(d, "uwas-fpm"), 0o700); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(d, "uwas-fpm", "php8419-fpm.conf")
	if err := os.Symlink(victim, conf); err != nil {
		t.Fatal(err)
	}
	if err := startFPMIn(t, d); err != nil {
		t.Fatalf("startFPMDaemon: %v", err)
	}
	if got, _ := os.ReadFile(victim); string(got) != "PRECIOUS" {
		t.Fatalf("symlink target was overwritten: %q", got)
	}
	fi, err := os.Lstat(conf)
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("config at %s should be a regular file, got %v (%v)", conf, fi, err)
	}
	if b, _ := os.ReadFile(conf); !strings.Contains(string(b), "[www]") {
		t.Errorf("config not written: %q", b)
	}
}

// A config directory other users can write to could have the config swapped
// after it is written, so it is refused.
func TestStartFPMDaemonRefusesWorldWritableConfigDir(t *testing.T) {
	d := t.TempDir()
	dir := filepath.Join(d, "uwas-fpm")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	err := startFPMIn(t, d)
	if err == nil || !strings.Contains(err.Error(), "writable by other users") {
		t.Fatalf("err = %v, want refusal for a world-writable config dir", err)
	}
	// Control: an owner-only directory is accepted.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := startFPMIn(t, d); err != nil {
		t.Fatalf("owner-only dir refused: %v", err)
	}
}
