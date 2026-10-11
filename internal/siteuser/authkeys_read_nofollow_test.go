//go:build linux

package siteuser

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// F6500: authorized_keys is checked with Lstat and read later. The tenant owns
// .ssh, so it can swap the file for a link to a root-only file in between;
// the read must refuse the link instead of copying that file's lines into the
// tenant-owned file root rewrites.
func TestAuthorizedKeysReadRefusesSwappedSymlink(t *testing.T) {
	snap := saveHooks()
	defer restoreHooks(snap)
	defer func() { authKeysReadFn = readAuthKeys }()
	runtimeGOOS = "linux"
	execCommandFn = fakeExecCommand
	osMkdirAllFn = os.MkdirAll
	osOpenFileFn = os.OpenFile

	k1, fp1 := testAuthorizedKey(t, 1)
	k2, _ := testAuthorizedKey(t, 2)
	k3, _ := testAuthorizedKey(t, 3)
	const secret = "ROOT-ONLY-CREDENTIAL-LINE"

	setup := func(swap bool) (webDir, keys, victim string) {
		root := t.TempDir()
		webDir = filepath.Join(root, "dom", "public_html")
		keys = filepath.Join(root, "dom", ".ssh", "authorized_keys")
		os.MkdirAll(filepath.Dir(keys), 0o700)
		os.MkdirAll(webDir, 0o755)
		os.WriteFile(keys, []byte(k1+"\n"+k2+"\n"), 0o600)
		victim = filepath.Join(root, "victim")
		os.WriteFile(victim, []byte(secret+"\n"+k1+"\n"), 0o600)
		authKeysReadFn = func(name string) ([]byte, error) {
			if swap && name == keys { // between the Lstat check and the read
				os.Remove(keys)
				os.Symlink(victim, keys)
			}
			return readAuthKeys(name)
		}
		return webDir, keys, victim
	}
	read := func(p string) string { b, _ := os.ReadFile(p); return string(b) }

	t.Run("control without swap removes only the target", func(t *testing.T) {
		webDir, keys, _ := setup(false)
		if err := RemoveSSHKeyForWebDir(webDir, "dom.example", fp1); err != nil {
			t.Fatal(err)
		}
		if got := read(keys); strings.Contains(got, k1) || !strings.Contains(got, k2) {
			t.Fatalf("control: %q", got)
		}
	})
	t.Run("remove", func(t *testing.T) {
		webDir, keys, victim := setup(true)
		if err := RemoveSSHKeyForWebDir(webDir, "dom.example", fp1); err == nil {
			t.Error("Remove followed a swapped symlink without error")
		}
		// A regular file at the path would be the tenant-owned copy root wrote.
		if fi, err := os.Lstat(keys); err == nil && fi.Mode().IsRegular() && strings.Contains(read(keys), secret) {
			t.Errorf("foreign file's line copied into authorized_keys: %q", read(keys))
		}
		if got := read(victim); !strings.Contains(got, secret) {
			t.Errorf("victim file modified: %q", got)
		}
	})
	t.Run("add", func(t *testing.T) {
		webDir, keys, victim := setup(true)
		if err := AddSSHKeyForWebDir(webDir, "dom.example", k3); err == nil {
			t.Error("Add followed a swapped symlink without error")
		}
		if strings.Contains(read(victim), k3) {
			t.Errorf("key appended through the link into the victim file: %q", read(victim))
		}
		_ = keys
	})
	t.Run("list", func(t *testing.T) {
		webDir, _, _ := setup(true)
		if got := ListSSHKeysForWebDir(webDir, "dom.example"); len(got) != 0 {
			t.Errorf("List returned the foreign file's lines: %v", got)
		}
	})
}

// A FIFO swapped in after the Lstat must not hang the privileged read.
func TestAuthorizedKeysReadDoesNotBlockOnFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "authorized_keys")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readAuthKeys(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("FIFO read succeeded, want an error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("readAuthKeys blocked on a FIFO")
	}
}
