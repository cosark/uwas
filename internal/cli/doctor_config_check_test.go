package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func stubDoctorExec(t *testing.T) {
	t.Helper()
	origExec, origLook, origStat := doctorExecCommand, doctorExecLookPath, doctorOsStat
	t.Cleanup(func() { doctorExecCommand, doctorExecLookPath, doctorOsStat = origExec, origLook, origStat })
	doctorExecCommand = func(string, ...string) *exec.Cmd { return exec.Command("echo", "mocked") }
	doctorExecLookPath = func(string) (string, error) { return "", fmt.Errorf("not found") }
	doctorOsStat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
}

// F14303: "uwas doctor" reported "Config ok" for any config path that merely
// existed. A file the loader rejects is the first thing a diagnostic must say.
func TestDoctorConfigCheckLoadsTheConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good.yaml", minimalValidConfig)
	broken := write("broken.yaml", "global: [unclosed\n")
	typo := write("typo.yaml", minimalValidConfig+"securty:\n  waf:\n    enabled: true\n")

	if c := checkCLI_Config(good); c.status != "ok" || c.message != good {
		t.Errorf("valid config: status %q message %q, want ok %q", c.status, c.message, good)
	}
	if c := checkCLI_Config(broken); c.status != "fail" {
		t.Errorf("config the loader rejects: status %q (%q), want fail", c.status, c.message)
	}
	if c := checkCLI_Config(typo); c.status != "warn" || !strings.Contains(c.message, "securty") {
		t.Errorf("config with an ignored key: status %q message %q, want warn naming securty", c.status, c.message)
	}
}

// F14303: doctor looked for /etc/uwas/uwas.yaml, ./uwas.yaml, $HOME/.uwas in
// that order; serve uses ./uwas.yaml, ./uwas.yml, ./.uwas, ~/.uwas, /etc/uwas.
// It diagnosed a different file than the one the server starts with (or none,
// for ./.uwas/uwas.yaml).
func TestDoctorDiagnosesTheConfigServeWouldUse(t *testing.T) {
	stubDoctorExec(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".uwas"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(".uwas", "uwas.yaml")
	if err := os.WriteFile(filepath.Join(dir, cfg), []byte(minimalValidConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	var err error
	out := captureStdout(t, func() { err = DoctorCommand(nil) })
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if !strings.Contains(out, "Config: "+cfg) {
		t.Errorf("doctor did not pick the config serve would use (%s):\n%s", cfg, out)
	}
}
