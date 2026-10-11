package htaccess

import (
	"net"
	"strings"
	"testing"
)

func convertString(t *testing.T, ht string) *RuleSet {
	t.Helper()
	ds, err := Parse(strings.NewReader(ht))
	if err != nil {
		t.Fatal(err)
	}
	return Convert(ds)
}

// F3000: <IfModule> around Order/Deny or an identifier-style module name must
// not drop the deny it carries.
func TestIfModuleAccessModulesEnforced(t *testing.T) {
	ip := net.ParseIP("203.0.113.9")
	cases := map[string]string{
		"authz_core":       "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n",
		"authz_host":       "<IfModule mod_authz_host.c>\nOrder deny,allow\nDeny from all\n</IfModule>\n",
		"access_compat":    "<IfModule mod_access_compat.c>\nOrder deny,allow\nDeny from all\n</IfModule>\n",
		"identifier":       "<IfModule authz_core_module>\nRequire all denied\n</IfModule>\n",
		"upper identifier": "<IfModule AUTHZ_CORE_MODULE>\nRequire all denied\n</IfModule>\n",
		"negated unloaded": "<IfModule !mod_php.c>\nRequire all denied\n</IfModule>\n",
	}
	for name, ht := range cases {
		if got := convertString(t, ht).AccessFor(ip); got != AccessDenied {
			t.Errorf("%s: got %v, want denied", name, got)
		}
	}
	// Unloaded module: block still skipped.
	if got := convertString(t, "<IfModule mod_security.c>\nRequire all denied\n</IfModule>\n").AccessFor(ip); got != AccessUnset {
		t.Errorf("unloaded module block applied: %v", got)
	}
}

// F3001: Convert and access evaluation agree on <IfModule> conditions.
func TestConvertIfModuleNegationAndIdentifier(t *testing.T) {
	cases := []struct {
		ht   string
		want int
	}{
		{"<IfModule mod_rewrite.c>\nRewriteRule ^a$ /b\n</IfModule>\n", 1},
		{"<IfModule rewrite_module>\nRewriteRule ^a$ /b\n</IfModule>\n", 1},
		{"<IfModule !mod_php.c>\nRewriteRule ^a$ /b\n</IfModule>\n", 1},
		{"<IfModule !mod_rewrite.c>\nRewriteRule ^a$ /b\n</IfModule>\n", 0},
		{"<IfModule mod_php.c>\nRewriteRule ^a$ /b\n</IfModule>\n", 0},
		{"<IfModule>\nRewriteRule ^a$ /b\n</IfModule>\n", 0},
	}
	for _, c := range cases {
		if got := len(convertString(t, c.ht).Rewrites); got != c.want {
			t.Errorf("%q: rewrites=%d want %d", c.ht, got, c.want)
		}
	}
}

// F3002: merging a block that sets AuthType must not erase an AuthUserFile
// declared elsewhere, or the directory silently becomes public.
func TestMergeAuthTypeKeepsAuthUserFile(t *testing.T) {
	cases := map[string]string{
		"top then block":   "AuthUserFile .htpasswd\n<IfModule mod_auth_basic.c>\nAuthType Basic\nAuthName x\n</IfModule>\n",
		"block then block": "<IfModule mod_authn_file.c>\nAuthUserFile .htpasswd\n</IfModule>\n<IfModule mod_auth_basic.c>\nAuthType Basic\n</IfModule>\n",
		"rejected abs":     "AuthUserFile /home/u/.htpasswd\n<IfModule mod_auth_basic.c>\nAuthType Basic\n</IfModule>\n",
	}
	for name, ht := range cases {
		if rs := convertString(t, ht); !AuthUserFileRequiresAuth(rs) {
			t.Errorf("%s: auth requirement lost", name)
		}
	}
	rs := convertString(t, "<IfModule mod_auth_basic.c>\nAuthType Basic\nAuthUserFile .a\n</IfModule>\n<IfModule mod_auth_basic.c>\nAuthType Basic\nAuthUserFile .b\n</IfModule>\n")
	if rs.AuthUserFile != ".b" {
		t.Errorf("later AuthUserFile should win, got %q", rs.AuthUserFile)
	}
}
