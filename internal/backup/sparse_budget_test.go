package backup

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// F14900: a tenant-made sparse file must not make a backup read and compress
// its apparent size; a fully allocated file of any size is still archived.
func TestAddDirToTarBoundsSparseFiles(t *testing.T) {
	oldMin, oldBudget := sparseMinApparent, sparseApparentBudget
	sparseMinApparent, sparseApparentBudget = 1<<20, 100<<20
	t.Cleanup(func() { sparseMinApparent, sparseApparentBudget = oldMin, oldBudget })

	dir := t.TempDir()
	makeSparse := func(name string, size int64) {
		t.Helper()
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(size); err != nil {
			t.Skipf("cannot make a sparse file here: %v", err)
		}
		f.Close()
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if alloc, ok := allocatedBytes(info); !ok || alloc > size/2 {
			t.Skip("filesystem does not keep files sparse")
		}
	}
	makeSparse("a-sparse.bin", 64<<20)       // within the budget
	makeSparse("b-sparse.bin", 64<<20)       // would exceed it: skipped
	makeSparse("c-tiny-sparse.bin", 512<<10) // under the minimum: always kept
	dense := bytes.Repeat([]byte("x"), 3<<20)
	if err := os.WriteFile(filepath.Join(dir, "d-dense.bin"), dense, 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := addDirToTarWith(tw, dir, "site", nil); err != nil {
		t.Fatalf("addDirToTar: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	got := map[string]int64{}
	tr := tar.NewReader(&buf)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			got[filepath.Base(h.Name)] = h.Size
		}
	}
	if got["a-sparse.bin"] != 64<<20 {
		t.Errorf("first sparse file within the budget missing or wrong size: %v", got)
	}
	if _, ok := got["b-sparse.bin"]; ok {
		t.Errorf("sparse file over the budget was archived: %v", got)
	}
	if got["c-tiny-sparse.bin"] != 512<<10 {
		t.Errorf("sparse file under the minimum was dropped: %v", got)
	}
	if got["d-dense.bin"] != int64(len(dense)) {
		t.Errorf("fully allocated file was dropped or truncated: %v", got)
	}
}
