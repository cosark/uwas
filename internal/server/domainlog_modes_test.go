//go:build !windows

package server

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
)

// F8100: per-domain access logs hold client IPs, URLs and user agents, so
// neither the active file, the gzip archive nor a log left world-readable by an
// earlier version may stay readable by everyone.
func TestDomainLogFilesAreNotWorldReadable(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)

	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	m := newDomainLogManager()
	defer m.Close()
	cfg := config.AccessLogConfig{Path: path, Rotate: config.RotateConfig{MaxSize: 300, MaxBackups: 10}}

	m.Write("log.test", cfg, "GET", "/"+strings.Repeat("a", 400), "192.0.2.1", "ua", 200, 1, time.Millisecond)
	m.bg.Wait()
	m.Write("log.test", cfg, "GET", "/after", "192.0.2.1", "ua", 200, 1, time.Millisecond)
	m.flushAll()
	m.bg.Wait()

	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) < 2 {
		t.Fatalf("want active log and archive, got %v (%v)", entries, err)
	}
	for _, e := range entries {
		info, _ := e.Info()
		if info.Mode().Perm()&0o007 != 0 {
			t.Errorf("%s mode %04o is world-accessible", e.Name(), info.Mode().Perm())
		}
	}
}

func TestDomainLogTightensExistingWorldReadableFile(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)

	path := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(path, []byte("old line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	m := newDomainLogManager()
	defer m.Close()
	m.Write("log.test", config.AccessLogConfig{Path: path}, "GET", "/", "192.0.2.1", "ua", 200, 1, time.Millisecond)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o007 != 0 {
		t.Errorf("existing log kept mode %04o", info.Mode().Perm())
	}
	// A log whose owner deliberately restricted it further is left alone.
	path2 := filepath.Join(t.TempDir(), "private.log")
	os.WriteFile(path2, nil, 0o600)
	m.Write("log.test2", config.AccessLogConfig{Path: path2}, "GET", "/", "192.0.2.1", "ua", 200, 1, time.Millisecond)
	if fi, _ := os.Stat(path2); fi.Mode().Perm() != 0o600 {
		t.Errorf("private log mode changed to %04o", fi.Mode().Perm())
	}
}
