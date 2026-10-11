//go:build linux

package deploy

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A checkout's package.json is tenant-controlled and read as the server: a
// FIFO or a symlink to /dev/zero must not hang or exhaust memory (F5600).
func TestPackageJSONSpecialFileDoesNotHang(t *testing.T) {
	// control: a regular package.json is still detected.
	ok := t.TempDir()
	if err := os.WriteFile(filepath.Join(ok, "package.json"), []byte(`{"scripts":{"build":"x"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := detectBuildCmds(ok); len(got) == 0 {
		t.Fatal("regular package.json produced no build commands")
	}

	run := func(t *testing.T, dir string) {
		t.Helper()
		done := make(chan struct{})
		go func() { detectBuildCmds(dir); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			if w, err := os.OpenFile(filepath.Join(dir, "package.json"), os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				w.Close()
			}
			<-done
			t.Fatal("blocked reading a special package.json")
		}
	}

	t.Run("fifo", func(t *testing.T) {
		dir := t.TempDir()
		if err := syscall.Mkfifo(filepath.Join(dir, "package.json"), 0o644); err != nil {
			t.Skipf("mkfifo: %v", err)
		}
		run(t, dir)
	})
	t.Run("symlink to dev zero", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Symlink("/dev/zero", filepath.Join(dir, "package.json")); err != nil {
			t.Fatal(err)
		}
		run(t, dir)
	})
	t.Run("oversized regular file is truncated, not slurped", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "package.json")
		if err := os.WriteFile(p, []byte(`{"scripts":{"build":"x"}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(p, packageJSONMaxBytes*8); err != nil {
			t.Fatal(err)
		}
		data, err := readPackageJSON(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) != packageJSONMaxBytes {
			t.Errorf("read %d bytes, want the %d cap", len(data), packageJSONMaxBytes)
		}
	})
}
