package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func convertApacheForTest(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "site.conf")
	src := "<VirtualHost *:80>\nServerName b.test\nDocumentRoot /var/www/b\n" + body + "</VirtualHost>\n"
	if err := os.WriteFile(conf, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return convertApacheToYAML(parseApacheConfig(f))
}

// F8901: access and redirect directives that `uwas migrate apache` cannot
// translate are reported at the top of the output, never dropped silently.
func TestMigrateApacheReportsUntranslatedAccessRules(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"directory require": {"<Directory /var/www/b/admin>\nRequire all denied\n</Directory>\n", "<Directory /var/www/b/admin>"},
		"location require":  {"<Location /secret>\nRequire ip 10.0.0.0/8\n</Location>\n", "<Location /secret>"},
		"order deny":        {"Order deny,allow\nDeny from all\n", "Deny from all"},
		"auth":              {"AuthType Basic\nAuthUserFile /etc/apache2/.htpasswd\nRequire valid-user\n", "AuthUserFile /etc/apache2/.htpasswd"},
		"redirect":          {"Redirect permanent /old http://b.test/new\n", "Redirect permanent /old"},
	}
	for name, c := range cases {
		out := convertApacheForTest(t, c.body)
		if !strings.HasPrefix(out, "# WARNING: not migrated") || !strings.Contains(out, "b.test: "+c.want) {
			t.Errorf("%s: output does not warn about %q:\n%s", name, c.want, out)
		}
	}
}

func TestMigrateApacheCleanVHostHasNoWarning(t *testing.T) {
	out := convertApacheForTest(t, "SSLEngine off\nProxyPass /api http://127.0.0.1:9000\n")
	if strings.Contains(out, "WARNING") {
		t.Errorf("clean vhost carries a warning:\n%s", out)
	}
	if !strings.Contains(out, "host: b.test") {
		t.Errorf("host lost:\n%s", out)
	}
}

func TestMigrateApacheWarningsSurviveVHostMerge(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "site.conf")
	src := "<VirtualHost *:80>\nServerName m.test\nDocumentRoot /var/www/m\n</VirtualHost>\n" +
		"<VirtualHost *:443>\nServerName m.test\nDocumentRoot /var/www/m\n<Directory /var/www/m/p>\nRequire all denied\n</Directory>\n</VirtualHost>\n"
	os.WriteFile(conf, []byte(src), 0o600)
	f, _ := os.Open(conf)
	defer f.Close()
	out := convertApacheToYAML(parseApacheConfig(f))
	if !strings.Contains(out, "m.test: <Directory /var/www/m/p>") {
		t.Errorf("warning of the merged https vhost lost:\n%s", out)
	}
	if strings.Count(out, "host: m.test") != 1 {
		t.Errorf("vhost pair not merged:\n%s", out)
	}
}
