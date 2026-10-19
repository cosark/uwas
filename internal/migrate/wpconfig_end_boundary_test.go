package migrate

// Regression tests for the updateWPConfigDB statement-boundary fix.
//
// The rewriter used to locate the end of an existing define statement with
// the first ");" in the text. When the OLD value already contained ");" —
// wp-config.php adopted by a migration is arbitrary owner-controlled content
// — that boundary landed inside the value and the tail of the old value
// leaked past the rewritten define, corrupting wp-config.php (invalid PHP)
// while the migration reported "done". The rewriter now scans to the value's
// closing quote with backslash-escape awareness and requires the ")" after
// it. The new-value escaping itself (backslash then apostrophe) is pinned by
// wpconfig_escape_test.go; these tests pin the OLD-content boundary.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rewriteWPConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wp-config.php")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("setup: write wp-config.php: %v", err)
	}
	var log strings.Builder
	updateWPConfigDB(path, "new_db", "new_user", "new_pass", &log)
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back wp-config.php: %v", err)
	}
	return string(after)
}

func countDefines(content, key string) int {
	return strings.Count(content, "define('"+key+"'")
}

// An old value containing ");" must be replaced in full — no tail may leak.
func TestUpdateWPConfigDBOldValueWithCloseParen(t *testing.T) {
	before := `<?php
define('DB_NAME', 'old_db');
define('DB_USER', 'old_user');
define('DB_PASSWORD', 'wo);rd');
define('DB_HOST', 'localhost');
require_once ABSPATH . 'wp-settings.php';
`
	after := rewriteWPConfig(t, before)

	if strings.Contains(after, "rd');") {
		t.Fatalf("tail of the old value leaked past the rewritten define:\n%s", after)
	}
	if n := countDefines(after, "DB_PASSWORD"); n != 1 {
		t.Fatalf("expected exactly one DB_PASSWORD define, got %d:\n%s", n, after)
	}
	if !strings.Contains(after, "define('DB_PASSWORD', 'new_pass');") {
		t.Fatalf("DB_PASSWORD not rewritten to the new value:\n%s", after)
	}
	if !strings.Contains(after, "require_once ABSPATH") {
		t.Fatalf("the rest of wp-config.php was not preserved:\n%s", after)
	}
}

// Same shape for another constant (DB_NAME). "xyz');" cannot occur in a
// correct result, so its presence proves old-value text leaked.
func TestUpdateWPConfigDBOldDBNameWithCloseParen(t *testing.T) {
	before := `<?php
define('DB_NAME', 'old);xyz');
define('DB_USER', 'old_user');
define('DB_PASSWORD', 'old_pass');
define('DB_HOST', 'localhost');
require_once ABSPATH . 'wp-settings.php';
`
	after := rewriteWPConfig(t, before)

	if strings.Contains(after, "xyz');") {
		t.Fatalf("tail of the old DB_NAME value leaked past the rewritten define:\n%s", after)
	}
	if n := countDefines(after, "DB_NAME"); n != 1 {
		t.Fatalf("expected exactly one DB_NAME define, got %d:\n%s", n, after)
	}
	if !strings.Contains(after, "define('DB_NAME', 'new_db');") {
		t.Fatalf("DB_NAME not rewritten to the new value:\n%s", after)
	}
}

// An escaped apostrophe in the OLD value must not end the scan early.
// "here');" cannot occur in a correct result (no value contains "here"),
// so its presence proves old-value text leaked.
func TestUpdateWPConfigDBOldValueWithEscapedQuote(t *testing.T) {
	before := `<?php
define('DB_PASSWORD', 'it\'s);here');
define('DB_NAME', 'old_db');
define('DB_USER', 'old_user');
define('DB_HOST', 'localhost');
require_once ABSPATH . 'wp-settings.php';
`
	after := rewriteWPConfig(t, before)

	if strings.Contains(after, "here');") {
		t.Fatalf("old value tail leaked past the rewritten define:\n%s", after)
	}
	if !strings.Contains(after, "define('DB_PASSWORD', 'new_pass');") {
		t.Fatalf("DB_PASSWORD not rewritten to the new value:\n%s", after)
	}
}

// Control: plain old values keep being rewritten in full.
func TestUpdateWPConfigDBStandardValuesStillRewritten(t *testing.T) {
	before := `<?php
define('DB_NAME', 'old_db');
define('DB_USER', 'old_user');
define('DB_PASSWORD', 'old_pass');
define('DB_HOST', 'old_host');
require_once ABSPATH . 'wp-settings.php';
`
	after := rewriteWPConfig(t, before)

	for _, want := range []string{
		"define('DB_NAME', 'new_db');",
		"define('DB_USER', 'new_user');",
		"define('DB_PASSWORD', 'new_pass');",
		"define('DB_HOST', 'localhost');",
	} {
		if !strings.Contains(after, want) {
			t.Fatalf("missing %q:\n%s", want, after)
		}
	}
	if strings.Contains(after, "old_db") || strings.Contains(after, "old_pass") {
		t.Fatalf("old values survived:\n%s", after)
	}
}

// Control: a define with no closing quote keeps being skipped unchanged
// (TestUpdateWPConfigDBMissingCloseParen's contract).
func TestUpdateWPConfigDBUnterminatedStillSkipped(t *testing.T) {
	before := "<?php\ndefine('DB_NAME', 'old'\n"
	after := rewriteWPConfig(t, before)
	if after != before {
		t.Fatalf("unterminated define was modified:\n%s", after)
	}
}
