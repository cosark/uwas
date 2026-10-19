package wordpress

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedWPConfig writes a wp-config.php with the given body under a temp web root
// and returns the root. Real files, real FixPermissions — the rewrite path is
// reached in-process, so this exercises the production code under test.
func seedWPConfig(t *testing.T, body string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"), []byte(body), 0600); err != nil {
		t.Fatalf("seed wp-config.php: %v", err)
	}
	return root
}

func readWPConfig(t *testing.T, root string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "wp-config.php"))
	if err != nil {
		t.Fatalf("read wp-config.php: %v", err)
	}
	return string(data)
}

const anchor = "require_once ABSPATH"

// TestFixPermissionsDoesNotDuplicateWPTempDir is the defect. FixPermissions
// rewrites wp-config.php in two sequential blocks: when FS_METHOD is missing it
// replaces the anchor with a string that inserts BOTH FS_METHOD and
// WP_TEMP_DIR, reassigning `content`; the second block then tests
// !strings.Contains(content, "WP_TEMP_DIR") against that already-rewritten
// string. So a config that already defines WP_TEMP_DIR but not FS_METHOD gets a
// SECOND define('WP_TEMP_DIR', ...) written beside the first. PHP emits
// "Constant WP_TEMP_DIR already defined" on every request for that site.
func TestFixPermissionsDoesNotDuplicateWPTempDir(t *testing.T) {
	// The realistic shape: WP 6.7+ ships WP_TEMP_DIR; an operator whose
	// wp-config.php has no FS_METHOD hits the first branch only.
	root := seedWPConfig(t, `<?php
define('DB_NAME', 'db');
define('WP_TEMP_DIR', '/var/www/tmp');
`+"\n"+anchor+` ABSPATH . 'wp-settings.php';\n`)

	if _, err := FixPermissions(root); err != nil {
		t.Fatalf("FixPermissions: %v", err)
	}

	got := readWPConfig(t, root)
	if n := strings.Count(got, "define('WP_TEMP_DIR'"); n != 1 {
		t.Errorf("WP_TEMP_DIR defined %d times, want 1; a site that already had it and "+
			"lacked FS_METHOD now emits \"Constant WP_TEMP_DIR already defined\" on every "+
			"request.\ngot:\n%s", n, got)
	}
	if n := strings.Count(got, "define('FS_METHOD'"); n != 1 {
		t.Errorf("FS_METHOD defined %d times, want 1 (it was missing and must be added once)", n)
	}
}

// TestFixPermissionsAddsBothDefinesWhenNeitherPresent is the control for the
// main path: with neither define present, both must be added exactly once.
func TestFixPermissionsAddsBothDefinesWhenNeitherPresent(t *testing.T) {
	root := seedWPConfig(t, "<?php\ndefine('DB_NAME', 'db');\n"+"\n"+anchor+" ABSPATH . 'wp-settings.php';\n")

	if _, err := FixPermissions(root); err != nil {
		t.Fatalf("FixPermissions: %v", err)
	}

	got := readWPConfig(t, root)
	if n := strings.Count(got, "define('FS_METHOD'"); n != 1 {
		t.Errorf("FS_METHOD defined %d times, want 1", n)
	}
	if n := strings.Count(got, "define('WP_TEMP_DIR'"); n != 1 {
		t.Errorf("WP_TEMP_DIR defined %d times, want 1", n)
	}
	if !strings.Contains(got, "require_once ABSPATH") {
		t.Error("the anchor require_once ABSPATH was lost")
	}
}

// TestFixPermissionsLeavesCompleteConfigAlone is the second control: a config
// that already has both defines must not be rewritten at all.
func TestFixPermissionsLeavesCompleteConfigAlone(t *testing.T) {
	body := "<?php\ndefine('FS_METHOD', 'direct');\ndefine('WP_TEMP_DIR', '/var/www/tmp');\n" +
		"\n" + anchor + " ABSPATH . 'wp-settings.php';\n"
	root := seedWPConfig(t, body)

	if _, err := FixPermissions(root); err != nil {
		t.Fatalf("FixPermissions: %v", err)
	}

	if got := readWPConfig(t, root); got != body {
		t.Errorf("complete wp-config.php was rewritten:\ngot:\n%s\nwant:\n%s", got, body)
	}
}

// TestFixPermissionsAddsWPTempDirWhenOnlyItIsMissing covers the branch where
// FS_METHOD is present and only WP_TEMP_DIR has to be added.
func TestFixPermissionsAddsWPTempDirWhenOnlyItIsMissing(t *testing.T) {
	root := seedWPConfig(t, "<?php\ndefine('FS_METHOD', 'direct');\n"+"\n"+anchor+" ABSPATH . 'wp-settings.php';\n")

	if _, err := FixPermissions(root); err != nil {
		t.Fatalf("FixPermissions: %v", err)
	}

	got := readWPConfig(t, root)
	if n := strings.Count(got, "define('WP_TEMP_DIR'"); n != 1 {
		t.Errorf("WP_TEMP_DIR defined %d times, want 1", n)
	}
	if n := strings.Count(got, "define('FS_METHOD'"); n != 1 {
		t.Errorf("FS_METHOD defined %d times, want 1 (it was already present)", n)
	}
}
