package filemanager

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F14601: List read the whole directory and lstat()ed every entry before the
// admin handler paginated, so one request on a directory a tenant filled with
// files cost memory and syscalls proportional to its size. A directory over
// maxListEntries is now refused.
func TestListRefusesDirectoryOverEntryCap(t *testing.T) {
	old := maxListEntries
	maxListEntries = 20
	t.Cleanup(func() { maxListEntries = old })

	fill := func(n int) string {
		d := t.TempDir()
		for i := 0; i < n; i++ {
			if err := os.WriteFile(filepath.Join(d, fmt.Sprintf("f%03d", i)), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return d
	}

	// An empty directory lists as empty (ReadDir(n) reports io.EOF for it).
	if es, err := List(fill(0), "."); err != nil || len(es) != 0 {
		t.Fatalf("empty directory: %d entries, err=%v", len(es), err)
	}
	// Exactly at the cap is still listed in full.
	if es, err := List(fill(20), "."); err != nil || len(es) != 20 {
		t.Fatalf("directory at the cap: %d entries, err=%v; want 20, nil", len(es), err)
	}
	// One past the cap is refused, with a message naming the limit.
	es, err := List(fill(21), ".")
	if err == nil || !strings.Contains(err.Error(), "more than 20 entries") {
		t.Fatalf("directory over the cap: %d entries, err=%v; want an error naming the cap", len(es), err)
	}
}
