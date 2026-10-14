//go:build linux

package siteuser

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// F20000: the append open of authorized_keys has no O_NONBLOCK. The tenant
// owns .ssh and can swap the file for a FIFO after the Lstat check and the
// read (both already guarded); a blocking O_WRONLY open of a reader-less FIFO
// then waits forever while authKeysMu is held, freezing key management for
// every site.
func TestAddSSHKeyDoesNotBlockOnFIFOSwap(t *testing.T) {
	snap := saveHooks()
	defer restoreHooks(snap)
	defer func() { authKeysReadFn = readAuthKeys }()
	runtimeGOOS = "linux"
	execCommandFn = fakeExecCommand
	osMkdirAllFn = os.MkdirAll
	osOpenFileFn = os.OpenFile

	k1, _ := testAuthorizedKey(t, 1)
	k2, _ := testAuthorizedKey(t, 2)

	setup := func(swap bool) (webDir, keys string) {
		root := t.TempDir()
		webDir = filepath.Join(root, "dom", "public_html")
		keys = filepath.Join(root, "dom", ".ssh", "authorized_keys")
		os.MkdirAll(filepath.Dir(keys), 0o700)
		os.MkdirAll(webDir, 0o755)
		os.WriteFile(keys, []byte(k1+"\n"), 0o600)
		authKeysReadFn = func(name string) ([]byte, error) {
			data, err := readAuthKeys(name)
			if swap && name == keys { // between the read and the append open
				os.Remove(keys)
				if err := syscall.Mkfifo(keys, 0o600); err != nil {
					t.Skip(err)
				}
			}
			return data, err
		}
		return webDir, keys
	}

	t.Run("control without swap appends", func(t *testing.T) {
		webDir, keys := setup(false)
		if err := AddSSHKeyForWebDir(webDir, "dom.example", k2); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(keys); len(b) == 0 {
			t.Fatal("control: empty file")
		}
	})
	t.Run("fifo swap", func(t *testing.T) {
		webDir, keys := setup(true)
		done := make(chan error, 1)
		go func() { done <- AddSSHKeyForWebDir(webDir, "dom.example", k2) }()
		select {
		case err := <-done:
			if err == nil {
				t.Error("Add into a swapped FIFO succeeded, want an error")
			}
		case <-time.After(3 * time.Second):
			// Release the stuck open so the goroutine and authKeysMu are freed.
			if r, err := os.OpenFile(keys, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
				defer r.Close()
			}
			<-done
			t.Fatal("EXPECTED: error returned promptly; ACTUAL: append open blocked on FIFO holding authKeysMu")
		}
	})
}
