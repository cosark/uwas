package wordpress

import (
	"os"
	"path/filepath"
	"testing"
)

// writeRO seeds wp-config.php under a fresh web root.
func writeRO(t *testing.T, body string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestParseWPConfigQuoteForms pins that DB_NAME/DB_USER/DB_HOST are read from
// every spelling PHP accepts. Only the single-quoted form was recognised, so a
// hand-written wp-config.php with double quotes showed empty DB fields in the
// panel and made deriveDBName treat the site's own schema as foreign.
func TestParseWPConfigQuoteForms(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"single (control)", "<?php\ndefine('DB_NAME', 'wpdb');\ndefine('DB_USER', 'wpu');\ndefine('DB_HOST', 'db.local');\n"},
		{"double", "<?php\ndefine(\"DB_NAME\", \"wpdb\");\ndefine(\"DB_USER\", \"wpu\");\ndefine(\"DB_HOST\", \"db.local\");\n"},
		{"spaced", "<?php\ndefine( 'DB_NAME' , 'wpdb' );\ndefine( \"DB_USER\", 'wpu' );\ndefine('DB_HOST',\"db.local\");\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeRO(t, tc.body)
			n, u, h := parseWPConfig(filepath.Join(root, "wp-config.php"))
			if n != "wpdb" || u != "wpu" || h != "db.local" {
				t.Errorf("EXPECTED: wpdb/wpu/db.local\nACTUAL: %q/%q/%q\nPROBLEM CONFIRMED", n, u, h)
			}
		})
	}
}

// TestDetectSiteURLQuoteForms is the same shape for WP_HOME/WP_SITEURL: a
// double-quoted define was ignored and wp-cli got the directory-derived --url
// (or none) instead of the configured one.
func TestDetectSiteURLQuoteForms(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"single (control)", "<?php\ndefine('WP_HOME', 'https://blog.example.com');\n"},
		{"double", "<?php\ndefine(\"WP_HOME\", \"https://blog.example.com\");\n"},
		{"siteurl spaced", "<?php\ndefine( 'WP_SITEURL' , \"https://blog.example.com\" );\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeRO(t, tc.body)
			if got := detectSiteURL(root); got != "https://blog.example.com" {
				t.Errorf("EXPECTED: https://blog.example.com\nACTUAL: %q\nPROBLEM CONFIRMED", got)
			}
		})
	}
}
