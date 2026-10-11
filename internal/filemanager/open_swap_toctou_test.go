package filemanager

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// swapAfterResolve makes evalSymlinks replace file with a symlink to target
// right after resolving file, i.e. after safePathResolved's containment check
// has passed and before the caller opens it.
func swapAfterResolve(t *testing.T, file, target string) {
	t.Helper()
	orig := evalSymlinks
	var once sync.Once
	evalSymlinks = func(p string) (string, error) {
		r, err := orig(p)
		if p == file {
			once.Do(func() {
				os.Remove(file)
				os.Symlink(target, file)
			})
		}
		return r, err
	}
	t.Cleanup(func() { evalSymlinks = orig })
}

// F6800: the file was opened by its unresolved path after the containment
// check, so a tenant swapping it for a symlink in between made the root-run
// file manager read or overwrite a file outside the web root.
func TestReadFileDoesNotFollowSwappedSymlink(t *testing.T) {
	base, outside := t.TempDir(), t.TempDir()
	secret := filepath.Join(outside, "secret")
	os.WriteFile(secret, []byte("SECRET"), 0o600)
	f := filepath.Join(base, "a.txt")
	os.WriteFile(f, []byte("mine"), 0o644)

	if b, err := ReadFile(base, "a.txt"); err != nil || string(b) != "mine" {
		t.Fatalf("control read = %q, %v", b, err)
	}
	swapAfterResolve(t, f, secret)
	b, err := ReadFile(base, "a.txt")
	if err == nil || strings.Contains(string(b), "SECRET") {
		t.Fatalf("read through a swapped symlink returned %q, err=%v", b, err)
	}
}

func TestWriteFileDoesNotFollowSwappedSymlink(t *testing.T) {
	for name, write := range map[string]func(base string) error{
		"WriteFile":  func(base string) error { return WriteFile(base, "b.txt", []byte("PWNED")) },
		"SaveUpload": func(base string) error { _, err := SaveUpload(base, "b.txt", strings.NewReader("PWNED")); return err },
	} {
		t.Run(name, func(t *testing.T) {
			base, outside := t.TempDir(), t.TempDir()
			victim := filepath.Join(outside, "victim")
			os.WriteFile(victim, []byte("ORIG"), 0o600)
			f := filepath.Join(base, "b.txt")
			os.WriteFile(f, []byte("mine"), 0o644)

			if err := write(base); err != nil {
				t.Fatalf("control write: %v", err)
			}
			if b, _ := os.ReadFile(f); string(b) != "PWNED" {
				t.Fatalf("control wrote %q", b)
			}
			os.WriteFile(f, []byte("mine"), 0o644)
			swapAfterResolve(t, f, victim)
			if err := write(base); err == nil {
				t.Error("write through a swapped symlink succeeded")
			}
			if got, _ := os.ReadFile(victim); string(got) != "ORIG" {
				t.Fatalf("outside file was overwritten: %q", got)
			}
		})
	}
}

// A symlink that stays inside the web root keeps working: only a link swapped
// in after the check is refused.
func TestInRootSymlinkStillReadableAndWritable(t *testing.T) {
	base := t.TempDir()
	os.MkdirAll(filepath.Join(base, "releases"), 0o755)
	os.WriteFile(filepath.Join(base, "releases", "f.txt"), []byte("v1"), 0o644)
	if err := os.Symlink(filepath.Join(base, "releases", "f.txt"), filepath.Join(base, "cur.txt")); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadFile(base, "cur.txt"); err != nil || string(b) != "v1" {
		t.Fatalf("read via in-root link = %q, %v", b, err)
	}
	if err := WriteFile(base, "cur.txt", []byte("v2")); err != nil {
		t.Fatalf("write via in-root link: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(base, "releases", "f.txt")); string(b) != "v2" {
		t.Fatalf("target = %q, want v2", b)
	}
}
