package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

// rotateWithLockedDir writes one line, makes the log directory read-only so
// the rotation rename fails, then writes a line that crosses max_size.
func rotateWithLockedDir(t *testing.T, lockDir bool) (dir, logPath string, m *domainLogManager, cfg config.AccessLogConfig) {
	t.Helper()
	dir = t.TempDir()
	logPath = filepath.Join(dir, "access.log")
	cfg = config.AccessLogConfig{Path: logPath, Rotate: config.RotateConfig{MaxSize: 600, MaxBackups: 3}}
	m = newDomainLogManager()
	m.Write("a.test", cfg, "GET", "/first-marker", "203.0.113.1", "ua", 200, 1, 0)
	if lockDir {
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	}
	m.Write("a.test", cfg, "GET", "/second-marker", "203.0.113.1", strings.Repeat("u", 700), 200, 1, 0)
	return dir, logPath, m, cfg
}

// A rotation whose rename fails leaves the active log in place; reopening it
// with O_TRUNC destroyed every line it held.
func TestRotateRenameFailureKeepsActiveLog(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir, logPath, m, cfg := rotateWithLockedDir(t, true)
	// Logging continues into the same file after the failed rotation.
	m.Write("a.test", cfg, "GET", "/third-marker", "203.0.113.1", "ua", 200, 1, 0)
	m.Close()
	_ = os.Chmod(dir, 0o755)

	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/first-marker", "/second-marker", "/third-marker"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("active log lost %s after failed rotation rename:\n%q", want, b)
		}
	}
}

// Control: a rotation that succeeds still starts an empty active log and
// archives the old lines.
func TestRotateSuccessStartsFreshLog(t *testing.T) {
	dir, logPath, m, cfg := rotateWithLockedDir(t, false)
	m.Write("a.test", cfg, "GET", "/third-marker", "203.0.113.1", "ua", 200, 1, 0)
	m.Close()

	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "/first-marker") || strings.Contains(string(b), "/second-marker") {
		t.Errorf("active log still holds pre-rotation lines:\n%q", b)
	}
	if !strings.Contains(string(b), "/third-marker") {
		t.Errorf("post-rotation line missing from active log:\n%q", b)
	}
	rotated := findRotatedFiles(logPath)
	if len(rotated) == 0 {
		t.Fatalf("no rotated archive in %s", dir)
	}
}
