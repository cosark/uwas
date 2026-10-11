package filemanager

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// swapDirOnResolve makes evalSymlinks replace the directory dir with a symlink
// to target right after resolving trigger: after the containment check has
// passed and before the operation runs.
func swapDirOnResolve(t *testing.T, trigger, dir, target string) {
	t.Helper()
	orig := evalSymlinks
	var once sync.Once
	evalSymlinks = func(p string) (string, error) {
		r, err := orig(p)
		if p == trigger && err == nil {
			once.Do(func() {
				os.Rename(dir, dir+".old")
				os.Symlink(target, dir)
			})
		}
		return r, err
	}
	t.Cleanup(func() { evalSymlinks = orig })
}

func parentSwapFixture(t *testing.T) (base, outside string) {
	t.Helper()
	base, outside = t.TempDir(), t.TempDir()
	os.Mkdir(filepath.Join(base, "d"), 0o755)
	os.WriteFile(filepath.Join(base, "d", "f"), []byte("mine"), 0o644)
	os.WriteFile(filepath.Join(outside, "f"), []byte("OUTSIDE"), 0o600)
	return base, outside
}

// F7100-F7103: the checked path was operated on by name, so a tenant swapping
// an ancestor directory for a symlink in between made the root-run file
// manager delete, list, read, write or create outside the web root. F6800
// only covered the final path component.
func TestDeleteDoesNotFollowSwappedParent(t *testing.T) {
	base, outside := parentSwapFixture(t)
	swapDirOnResolve(t, filepath.Join(base, "d", "f"), filepath.Join(base, "d"), outside)
	Delete(base, "d/f")
	if _, err := os.Stat(filepath.Join(outside, "f")); err != nil {
		t.Fatalf("file outside the web root was deleted: %v", err)
	}
}

func TestDeleteStillRemovesInsideFile(t *testing.T) {
	base, _ := parentSwapFixture(t)
	if err := Delete(base, "d/f"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "d", "f")); !os.IsNotExist(err) {
		t.Fatalf("control: file not removed: %v", err)
	}
}

func TestListDoesNotFollowSwappedDir(t *testing.T) {
	base, outside := parentSwapFixture(t)
	os.WriteFile(filepath.Join(outside, "secret-name.txt"), []byte("x"), 0o600)
	if es, err := List(base, "d"); err != nil || len(es) != 1 || es[0].Name != "f" {
		t.Fatalf("control listing = %v, %v", es, err)
	}
	swapDirOnResolve(t, filepath.Join(base, "d"), filepath.Join(base, "d"), outside)
	es, _ := List(base, "d")
	for _, e := range es {
		if e.Name == "secret-name.txt" {
			t.Fatalf("listed a directory outside the web root: %v", es)
		}
	}
}

func TestReadWriteDoNotFollowSwappedParent(t *testing.T) {
	base, outside := parentSwapFixture(t)
	swapDirOnResolve(t, filepath.Join(base, "d", "f"), filepath.Join(base, "d"), outside)
	b, _ := ReadFile(base, "d/f")
	if strings.Contains(string(b), "OUTSIDE") {
		t.Fatalf("read a file outside the web root: %q", b)
	}

	base2, outside2 := parentSwapFixture(t)
	swapDirOnResolve(t, filepath.Join(base2, "d", "f"), filepath.Join(base2, "d"), outside2)
	WriteFile(base2, "d/f", []byte("PWNED"))
	if got, _ := os.ReadFile(filepath.Join(outside2, "f")); string(got) != "OUTSIDE" {
		t.Fatalf("file outside the web root was overwritten: %q", got)
	}
}

func TestSaveUploadDoesNotFollowSwappedParent(t *testing.T) {
	base, outside := parentSwapFixture(t)
	swapDirOnResolve(t, filepath.Join(base, "d", "f"), filepath.Join(base, "d"), outside)
	SaveUpload(base, "d/f", strings.NewReader("PWNED"))
	if got, _ := os.ReadFile(filepath.Join(outside, "f")); string(got) != "OUTSIDE" {
		t.Fatalf("file outside the web root was overwritten: %q", got)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 1 {
		t.Fatalf("staging file left outside the web root: %v", ents)
	}
}

func TestCreateDirDoesNotFollowSwappedParent(t *testing.T) {
	base, outside := parentSwapFixture(t)
	if err := CreateDir(base, "d/ok"); err != nil {
		t.Fatalf("control: %v", err)
	}
	swapDirOnResolve(t, filepath.Join(base, "d"), filepath.Join(base, "d"), outside)
	CreateDir(base, "d/newdir")
	if _, err := os.Stat(filepath.Join(outside, "newdir")); err == nil {
		t.Fatal("directory created outside the web root")
	}
}

// A symlink that stays inside the web root keeps working.
func TestOperationsFollowInRootSymlink(t *testing.T) {
	base := t.TempDir()
	os.Mkdir(filepath.Join(base, "real"), 0o755)
	os.WriteFile(filepath.Join(base, "real", "f"), []byte("data"), 0o644)
	os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "link"))
	if b, err := ReadFile(base, "link/f"); err != nil || string(b) != "data" {
		t.Fatalf("read via in-root symlink = %q, %v", b, err)
	}
	if _, err := SaveUpload(base, "link/g", strings.NewReader("up")); err != nil {
		t.Fatalf("upload via in-root symlink: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(base, "real", "g")); string(got) != "up" {
		t.Fatalf("upload landed as %q", got)
	}
	if err := CreateDir(base, "link/sub"); err != nil {
		t.Fatalf("mkdir via in-root symlink: %v", err)
	}
	if err := Delete(base, "link/g"); err != nil {
		t.Fatalf("delete via in-root symlink: %v", err)
	}
}
