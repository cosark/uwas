package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rewriteWPDB(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "wp-config.php")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	updateWPConfigDB(p, "newdb", "newuser", "newpass", &log)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// updateWPConfigDB must replace the DB defines whatever quoting or spacing the
// foreign wp-config.php used; otherwise the old (remote) credentials survive
// while the migration log claims they were updated.
func TestUpdateWPConfigDBDefineForms(t *testing.T) {
	cases := map[string]string{
		"single-quoted": "<?php\ndefine('DB_NAME', 'old');\ndefine('DB_USER', 'old');\ndefine('DB_PASSWORD', 'old');\ndefine('DB_HOST', 'old');\n",
		"double-quoted": "<?php\ndefine(\"DB_NAME\", \"old\");\ndefine(\"DB_USER\", \"old\");\ndefine(\"DB_PASSWORD\", \"old\");\ndefine(\"DB_HOST\", \"old\");\n",
		"spaced":        "<?php\ndefine( 'DB_NAME', 'old' );\ndefine( 'DB_USER', 'old' );\ndefine( 'DB_PASSWORD', 'old' );\ndefine( 'DB_HOST', 'old' );\n",
		"mixed quoting": "<?php\ndefine('DB_NAME', \"old\");\ndefine(\"DB_USER\", 'old');\ndefine( \"DB_PASSWORD\" , \"old\" );\ndefine('DB_HOST',\t'old');\n",
		"escaped quote": "<?php\ndefine(\"DB_NAME\", \"o\\\"ld\");\ndefine('DB_USER', 'o\\'ld');\ndefine(\"DB_PASSWORD\", \"x);y\");\ndefine('DB_HOST', 'old');\n",
	}
	for name, in := range cases {
		out := rewriteWPDB(t, in)
		for _, want := range []string{"define('DB_NAME', 'newdb')", "define('DB_USER', 'newuser')", "define('DB_PASSWORD', 'newpass')", "define('DB_HOST', 'localhost')"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: missing %q in:\n%s", name, want, out)
			}
		}
		if strings.Contains(out, "old") || strings.Contains(out, "x);y") {
			t.Errorf("%s: old value survived:\n%s", name, out)
		}
	}

	// Neighbouring defines must be left alone, including a key that merely
	// starts with a DB define's name.
	out := rewriteWPDB(t, "<?php\ndefine(\"DB_CHARSET\", \"utf8\");\ndefine('DB_NAME_EXTRA', 'keep');\ndefine(\"DB_NAME\", \"old\");\n")
	if !strings.Contains(out, `define("DB_CHARSET", "utf8")`) || !strings.Contains(out, "define('DB_NAME_EXTRA', 'keep')") {
		t.Errorf("unrelated defines were modified:\n%s", out)
	}
	if !strings.Contains(out, "define('DB_NAME', 'newdb')") {
		t.Errorf("DB_NAME not rewritten:\n%s", out)
	}
}
