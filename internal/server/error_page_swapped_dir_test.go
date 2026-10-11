package server

import (
	"os"
	"path/filepath"
	"testing"
)

// F6901: readErrorPage must judge containment from a fresh resolution. With
// pathsafe's cached target resolution a directory swapped for a symlink to an
// outside directory kept passing, and the open (which only refuses a symlinked
// last component) read an outside file into the error page.
func TestReadErrorPageRefusesSwappedDirectorySymlink(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "root")
	outside := filepath.Join(tmp, "outside")
	for _, d := range []string{filepath.Join(root, "errors"), filepath.Join(root, "real"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(outside, "page.html"), []byte("SECRET-OUTSIDE"), 0o644)
	os.WriteFile(filepath.Join(root, "errors", "page.html"), []byte("INSIDE"), 0o644)
	os.WriteFile(filepath.Join(root, "real", "page.html"), []byte("REAL"), 0o644)
	if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}

	// Warm the resolution cache the way an earlier error response would.
	for page, want := range map[string]string{"errors/page.html": "INSIDE", "alias/page.html": "REAL"} {
		if b, err := readErrorPage(root, page); err != nil || string(b) != want {
			t.Fatalf("warm %s = %q, %v; want %q", page, b, err, want)
		}
	}

	os.RemoveAll(filepath.Join(root, "errors"))
	if err := os.Symlink(outside, filepath.Join(root, "errors")); err != nil {
		t.Fatal(err)
	}
	if b, err := readErrorPage(root, "errors/page.html"); err == nil {
		t.Errorf("page behind a swapped-in outside directory symlink was read: %q", b)
	}
	// Controls: a symlinked directory that stays inside the root still works.
	if b, err := readErrorPage(root, "alias/page.html"); err != nil || string(b) != "REAL" {
		t.Errorf("in-root symlinked directory: %q, %v; want REAL", b, err)
	}
}
