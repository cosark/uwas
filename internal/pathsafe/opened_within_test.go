package pathsafe

import (
	"os"
	"path/filepath"
	"testing"
)

// F7210: the containment check that precedes an open leaves a window for a
// symlink swap; OpenedWithin confirms the opened handle afterwards.
func TestOpenedWithin(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "root")
	outside := filepath.Join(tmp, "outside")
	for _, d := range []string{root, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, body string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(root, "f.txt")
	write(file, "inside")
	write(filepath.Join(outside, "o.txt"), "outside")
	rootLink := filepath.Join(tmp, "rootlink")
	if err := os.Symlink(root, rootLink); err != nil {
		t.Fatal(err)
	}

	open := func(p string) *os.File {
		t.Helper()
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}

	// Control: an untouched file, reached through a symlinked base too.
	if !OpenedWithin(root, file, open(file)) {
		t.Error("untouched file rejected")
	}
	if !OpenedWithin(rootLink, filepath.Join(rootLink, "f.txt"), open(filepath.Join(rootLink, "f.txt"))) {
		t.Error("file under a symlinked base rejected")
	}

	// Opened inside, then the path is swapped for an outside symlink.
	f := open(file)
	os.Remove(file)
	if err := os.Symlink(filepath.Join(outside, "o.txt"), file); err != nil {
		t.Fatal(err)
	}
	if OpenedWithin(root, file, f) {
		t.Error("handle opened before the swap accepted")
	}
	// Opened after the swap: the handle is the outside file.
	if OpenedWithin(root, file, open(file)) {
		t.Error("outside file opened through a swapped symlink accepted")
	}
}
