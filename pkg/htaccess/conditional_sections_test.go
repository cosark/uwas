package htaccess

import (
	"net"
	"strings"
	"testing"
)

func conditionalRules(t *testing.T, src string) *RuleSet {
	t.Helper()
	d, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return Convert(d)
}

// <IfVersion> and <IfDefine> are decided (Apache 2.4, no -D flags); a denial
// inside an active one must be enforced (F5200).
func TestIfVersionIfDefineDecided(t *testing.T) {
	ip := net.ParseIP("1.2.3.4")
	tests := []struct {
		name string
		open string
		want AccessDecision
	}{
		{"ge 2.4", "<IfVersion >= 2.4>", AccessDenied},
		{"eq 2.4 partial", "<IfVersion = 2.4>", AccessDenied},
		{"gt 2.2", "<IfVersion > 2.2>", AccessDenied},
		{"negated lt", "<IfVersion !< 2.4>", AccessDenied},
		{"regex", "<IfVersion ~ ^2\\.4>", AccessDenied},
		{"lt 2.4", "<IfVersion < 2.4>", AccessUnset},
		{"ge 2.5", "<IfVersion >= 2.5>", AccessUnset},
		{"eq 2.2", "<IfVersion = 2.2>", AccessUnset},
		{"define negated", "<IfDefine !NOPE>", AccessDenied},
		{"define set", "<IfDefine NOPE>", AccessUnset},
	}
	for _, tt := range tests {
		closeTag := "</" + strings.Fields(strings.Trim(tt.open, "<>"))[0] + ">"
		rs := conditionalRules(t, tt.open+"\nRequire all denied\n"+closeTag+"\n")
		if got := rs.AccessFor(ip); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

// A <FilesMatch> inside an active <IfVersion> still reaches the file checks.
func TestIfVersionFilesMatchDenies(t *testing.T) {
	rs := conditionalRules(t, "<IfVersion >= 2.4>\n<FilesMatch \"\\.sql$\">\nRequire all denied\n</FilesMatch>\n</IfVersion>\n")
	if !FilesMatchDenies(rs, "dump.sql") {
		t.Error("dump.sql not denied inside <IfVersion >= 2.4>")
	}
	if FilesMatchDenies(rs, "index.html") {
		t.Error("index.html denied")
	}
}

// An <If> expression cannot be evaluated here; a denial inside it fails
// closed instead of being dropped (F5201), while sections that cannot deny
// the directory stay inert.
func TestUnevaluableConditionalFailsClosed(t *testing.T) {
	ip := net.ParseIP("1.2.3.4")
	deny := map[string]string{
		"if require":  "<If \"%{REQUEST_URI} =~ m#^/s#\">\nRequire all denied\n</If>\n",
		"if deny":     "<If \"true\">\nOrder allow,deny\nDeny from all\n</If>\n",
		"else ip":     "<If \"false\">\nRequire all granted\n</If>\n<Else>\nRequire ip 10.0.0.0/8\n</Else>\n",
		"nested":      "<If \"true\">\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n</If>\n",
		"ifdirective": "<IfDirective Require>\nRequire all denied\n</IfDirective>\n",
	}
	for n, src := range deny {
		if got := conditionalRules(t, src).AccessFor(ip); got != AccessDenied {
			t.Errorf("%s: got %v, want AccessDenied", n, got)
		}
	}
	inert := map[string]string{
		"header only":    "<If \"%{HTTPS} == 'on'\">\nHeader set X-A 1\n</If>\n",
		"granted only":   "<If \"true\">\nRequire all granted\n</If>\n",
		"files in if":    "<If \"true\">\n<FilesMatch \"\\.sql$\">\nRequire all denied\n</FilesMatch>\n</If>\n",
		"plain":          "Header set X-A 1\n",
		"inactive vers.": "<IfVersion < 2.4>\nRequire all denied\n</IfVersion>\n",
	}
	for n, src := range inert {
		if got := conditionalRules(t, src).AccessFor(ip); got != AccessUnset {
			t.Errorf("%s: got %v, want AccessUnset", n, got)
		}
	}
	// FilesMatch body with an unevaluable <If> denial.
	rs := conditionalRules(t, "<FilesMatch \"\\.sql$\">\n<If \"true\">\nRequire all denied\n</If>\n</FilesMatch>\n")
	if !FilesMatchDenies(rs, "a.sql") {
		t.Error("a.sql not denied by <If> inside <FilesMatch>")
	}
}
