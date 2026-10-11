package migrate

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// F8900: access rules the nginx converter cannot express must be reported, not
// dropped silently.
func TestNginxUntranslatedAccessRulesAreReported(t *testing.T) {
	wrap := func(body string) string {
		return "server {\n server_name b.test;\n root /var/www/b;\n" + body + "}\n"
	}
	cases := map[string]struct {
		body string
		want string
	}{
		"regex deny":       {"location ~ \\.env$ {\n deny all;\n}\n", "deny all"},
		"auth_basic":       {"location /admin/ {\n auth_basic \"x\";\n auth_basic_user_file /etc/nginx/.htpasswd;\n}\n", "auth_basic"},
		"allow list":       {"location /ops/ {\n allow 10.0.0.0/8;\n}\n", "allow 10.0.0.0/8"},
		"server auth":      {"auth_basic \"x\";\n", "server auth_basic"},
		"one-line regex":   {"location ~* \\.sql$ { deny all; }\n", "deny all"},
		"internal":         {"location /i/ {\n internal;\n}\n", "internal"},
		"root deny":        {"location / {\n deny all;\n}\n", "deny all"},
		"deny one network": {"location /x/ {\n deny 203.0.113.0/24;\n}\n", "deny 203.0.113.0/24"},
	}
	for name, c := range cases {
		out, warnings, err := NginxToYAMLWithWarnings(strings.NewReader(wrap(c.body)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(warnings) == 0 || !strings.Contains(strings.Join(warnings, "\n"), c.want) {
			t.Errorf("%s: warnings=%q, want one mentioning %q", name, warnings, c.want)
		}
		if !strings.HasPrefix(warnings[0], "b.test: ") {
			t.Errorf("%s: warning %q does not name the site", name, warnings[0])
		}
		commented, err := NginxToYAML(strings.NewReader(wrap(c.body)))
		if err != nil || !strings.HasPrefix(commented, "# WARNING:") {
			t.Errorf("%s: NginxToYAML output does not start with a WARNING line: %q", name, commented)
		}
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(commented), &doc); err != nil {
			t.Errorf("%s: output with warnings is not valid YAML: %v", name, err)
		}
		if strings.Contains(out, "WARNING") {
			t.Errorf("%s: the warning-free form must not embed comments", name)
		}
	}
}

func TestNginxTranslatableRulesProduceNoWarning(t *testing.T) {
	src := "server {\n server_name a.test;\n root /var/www/a;\n location /private/ { deny all; }\n location /api/ {\n proxy_pass http://127.0.0.1:9000;\n auth_basic off;\n }\n}\n"
	out, warnings, err := NginxToYAMLWithWarnings(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %q, want none", warnings)
	}
	if !strings.Contains(out, "/private/") {
		t.Errorf("prefix deny not carried over as blocked_paths:\n%s", out)
	}
	commented, _ := NginxToYAML(strings.NewReader(src))
	if strings.Contains(commented, "WARNING") {
		t.Errorf("clean migration must not carry a WARNING line: %q", commented)
	}
}
