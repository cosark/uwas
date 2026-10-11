package wordpress

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F11301: "a.b.com" and "a-b.com" both map to wp_a_b_com, which is also the
// default MySQL user; a taken name must not be handed to a second host.
func TestDeriveDBNameAvoidsTakenSchema(t *testing.T) {
	orig := databaseExistsFn
	defer func() { databaseExistsFn = orig }()
	taken := map[string]bool{"wp_a_b_com": true}
	databaseExistsFn = func(name string) bool { return taken[name] }

	if got := deriveDBName("other.com", t.TempDir()); got != "wp_other_com" {
		t.Errorf("untaken name changed: %q", got)
	}
	got := deriveDBName("a-b.com", t.TempDir())
	if got == "wp_a_b_com" || !strings.HasPrefix(got, "wp_a_b_com_") || len(got) > 32 {
		t.Errorf("a-b.com -> %q, want a hashed name distinct from the taken wp_a_b_com", got)
	}

	// A reinstall of the same site keeps its schema: its own wp-config.php names it.
	root := t.TempDir()
	cfg := "<?php\ndefine( 'DB_NAME', 'wp_a_b_com' );\n"
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := deriveDBName("a.b.com", root); got != "wp_a_b_com" {
		t.Errorf("reinstall renamed its schema: %q", got)
	}
}
