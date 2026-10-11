package migrate

import (
	"path/filepath"
	"strings"
	"testing"
)

// F11300: "a.b.com" and "a-b.com" both map to a_b_com_db; the dump import
// replaces the tables of the schema it lands in, so a taken derived name must
// not be reused for another host.
func TestCloneDerivedDBNameAvoidsTakenSchema(t *testing.T) {
	origFiles, origDB, origChown, origExists := runCloneFiles, runCloneDB, runCloneChown, cloneDBExists
	defer func() {
		runCloneFiles, runCloneDB, runCloneChown, cloneDBExists = origFiles, origDB, origChown, origExists
	}()

	taken := map[string]bool{"a_b_com_db": true}
	cloneDBExists = func(name string) bool { return taken[name] }
	var imported string
	runCloneFiles = func(src, dst string, log *strings.Builder) error { return nil }
	runCloneDB = func(srcDB, dstDB, user, pass string, log *strings.Builder) error { imported = dstDB; return nil }
	runCloneChown = func(root string) {}

	run := func(domain string) string {
		base := t.TempDir()
		imported = ""
		res := Clone(CloneRequest{SourceDomain: "src.example", TargetDomain: domain,
			SourceRoot: filepath.Join(base, "src"), TargetRoot: filepath.Join(base, "dst"), SourceDB: "prod_db"})
		if res.Status != "done" {
			t.Fatalf("clone %s: %s %s", domain, res.Status, res.Error)
		}
		return imported
	}

	if got := run("other.com"); got != "other_com_db" {
		t.Errorf("untaken name changed: %q", got)
	}
	got := run("a-b.com")
	if got == "a_b_com_db" || !strings.HasPrefix(got, "a_b_com_db_") || len(got) > 60 {
		t.Errorf("a-b.com -> %q, want a hashed name distinct from the taken a_b_com_db", got)
	}
	if again := run("a-b.com"); again != got {
		t.Errorf("hashed name not stable: %q vs %q", again, got)
	}
	if got := run("a.b.com"); got == "a_b_com_db" {
		// a.b.com owns the plain name only while it is free; once taken it
		// must not be imported over either (the existing schema may be its
		// own earlier clone, which a fresh clone must not clobber silently).
		t.Errorf("taken schema reused for a.b.com: %q", got)
	}

	// An explicit target_db is the caller's decision and is left alone.
	imported = ""
	base := t.TempDir()
	Clone(CloneRequest{SourceDomain: "src.example", TargetDomain: "a-b.com", TargetDB: "a_b_com_db",
		SourceRoot: filepath.Join(base, "src"), TargetRoot: filepath.Join(base, "dst"), SourceDB: "prod_db"})
	if imported != "a_b_com_db" {
		t.Errorf("explicit target_db rewritten to %q", imported)
	}
}
