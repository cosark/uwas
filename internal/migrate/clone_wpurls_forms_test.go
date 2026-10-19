package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runWPURLs(t *testing.T, content string) (string, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "wp-config.php")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	updateWPConfigURLs(p, "staging.example.com", &log)
	b, _ := os.ReadFile(p)
	return string(b), log.String()
}

// TestUpdateWPConfigURLsSourceForms pins that a cloned wp-config.php ends up
// defining WP_HOME/WP_SITEURL as the target domain whatever form the source
// file used: PHP keeps the first definition of a constant, so a stale define
// the rewrite missed (double quotes, spacing) wins, and a file without the
// exact "require_once ABSPATH" text lost its defines altogether — the clone
// then served the source site's URL from the database.
func TestUpdateWPConfigURLsSourceForms(t *testing.T) {
	cases := map[string]string{
		"canonical":                  "<?php\ndefine('WP_HOME', 'https://prod.com');\nrequire_once ABSPATH . 'wp-settings.php';\n",
		"paren require, WP_HOME set": "<?php\ndefine('WP_HOME', 'https://prod.com');\nrequire_once(ABSPATH . 'wp-settings.php');\n",
		"paren require, no define":   "<?php\n$table_prefix = 'wp_';\nrequire_once(ABSPATH . 'wp-settings.php');\n",
		"plain require":              "<?php\nrequire ABSPATH . 'wp-settings.php';\n",
		"double-quoted define":       "<?php\ndefine(\"WP_HOME\", \"https://prod.com\");\nrequire_once ABSPATH . 'wp-settings.php';\n",
		"spaced define":              "<?php\ndefine( 'WP_SITEURL', 'https://prod.com' );\nrequire_once ABSPATH . 'wp-settings.php';\n",
		"no require at all":          "<?php\ndefine('WP_HOME', 'https://prod.com');\necho 1;\n",
		"duplicate stale defines":    "<?php\ndefine('WP_HOME', 'https://prod.com');\ndefine('WP_HOME', 'https://prod2.com');\nrequire_once ABSPATH . 'wp-settings.php';\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			out, _ := runWPURLs(t, in)
			if strings.Count(out, "'WP_HOME', 'https://staging.example.com'") != 1 ||
				strings.Count(out, "'WP_SITEURL', 'https://staging.example.com'") != 1 {
				t.Errorf("target defines missing or duplicated:\n%s", out)
			}
			if strings.Contains(out, "prod") {
				t.Errorf("stale source URL survived:\n%s", out)
			}
		})
	}
}

func TestUpdateWPConfigURLsKeepsOtherDefinesAndNoAnchorIsReported(t *testing.T) {
	out, _ := runWPURLs(t, "<?php\ndefine('DB_NAME', 'x');\ndefine(\"WP_HOME\", 'https://prod.com');\nrequire_once ABSPATH . 'a.php';\n")
	if !strings.Contains(out, "define('DB_NAME', 'x');") {
		t.Errorf("unrelated define lost:\n%s", out)
	}

	// No opening tag and no require: nothing to anchor to, so nothing may be
	// logged as set.
	out, log := runWPURLs(t, "just text\n")
	if out != "just text\n" || strings.Contains(log, "set to") {
		t.Errorf("unanchorable file changed or reported as set: %q / %q", out, log)
	}
}
