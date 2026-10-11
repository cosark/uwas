package htaccess

import (
	"net"
	"testing"
)

// F12700: a section whose condition UWAS cannot decide must not lift a
// restriction by being dropped. Two shapes still did: an <IfModule> for a module
// the table does not list (mod_auth_digest, mod_authnz_ldap, ... — blocks that
// carry authentication or a denial) and a 2.2 allowlist ("Order Allow,Deny" with
// no "Allow from all") inside a section that cannot be decided.
func TestUndecidedSectionsKeepTheirRestrictions(t *testing.T) {
	outside := net.ParseIP("198.51.100.7")
	cases := []struct {
		name string
		src  string
		want AccessDecision
	}{
		// restrictions that must survive
		{"allowlist inside <If>", "<If \"%{HTTP_HOST} == 'x'\">\nOrder Allow,Deny\nAllow from 10.0.0.0/8\n</If>\n", AccessDenied},
		{"Mutual-failure allowlist inside <If>", "<If \"x\">\nOrder Mutual-failure\nAllow from 10.0.0.0/8\n</If>\n", AccessDenied},
		{"allowlist with no Allow line inside <If>", "<If \"x\">\nOrder Allow,Deny\n</If>\n", AccessDenied},
		{"auth inside unlisted module", "<IfModule mod_auth_digest.c>\nAuthType Digest\nAuthUserFile /srv/.htdigest\nRequire valid-user\n</IfModule>\n", AccessDenied},
		{"ldap inside unlisted module", "<IfModule mod_authnz_ldap.c>\nRequire ldap-group cn=a\n</IfModule>\n", AccessDenied},
		{"deny inside unlisted module", "<IfModule mod_authz_owner.c>\nRequire all denied\n</IfModule>\n", AccessDenied},
		{"allowlist inside unlisted module", "<IfModule mod_made_up.c>\nOrder Allow,Deny\nAllow from 10.0.0.0/8\n</IfModule>\n", AccessDenied},
		{"<IfModule> without a name", "<IfModule>\nRequire all denied\n</IfModule>\n", AccessDenied},
		// controls: sections that really do not restrict, or are decided
		{"Allow from all inside <If> is no restriction", "<If \"x\">\nOrder Allow,Deny\nAllow from all\n</If>\n", AccessUnset},
		{"default order allowlist inside <If> is no restriction", "<If \"x\">\nAllow from 10.0.0.0/8\n</If>\n", AccessUnset},
		{"listed-as-not-loaded module stays inactive", "<IfModule mod_php.c>\nRequire all denied\n</IfModule>\n", AccessUnset},
		{"non-restricting unlisted module is ignored", "<IfModule mod_pagespeed_ap24.c>\nModPagespeed on\n</IfModule>\n", AccessUnset},
		{"negated unlisted module applies", "<IfModule !mod_made_up.c>\nRequire all denied\n</IfModule>\n", AccessDenied},
		{"listed loaded module applies", "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n", AccessDenied},
		{"negated loaded module is inactive", "<IfModule !mod_rewrite.c>\nRequire all denied\n</IfModule>\n", AccessUnset},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rs := conditionalRules(t, c.src)
			if got := rs.AccessForMethod(outside, "GET"); got != c.want {
				t.Errorf("access = %v, want %v", got, c.want)
			}
		})
	}
}

// A per-file denial and the "no PHP here" switch inside a module section the
// table does not list stay in force too.
func TestUnlistedModuleSectionKeepsFileDenyAndPHPSwitch(t *testing.T) {
	rs := conditionalRules(t, "<IfModule mod_made_up.c>\n<FilesMatch \"\\.sql$\">\nRequire all denied\n</FilesMatch>\n</IfModule>\n")
	if !FilesMatchDeniesForMethod(rs, "dump.sql", net.ParseIP("198.51.100.7"), "GET") {
		t.Error("FilesMatch denial inside an unlisted module section was dropped")
	}
	if FilesMatchDeniesForMethod(rs, "readme.txt", net.ParseIP("198.51.100.7"), "GET") {
		t.Error("control: readme.txt must not be denied")
	}

	for _, mod := range []string{"mod_php74.c", "mod_php7.c", "php7_module"} {
		php := conditionalRules(t, "<IfModule "+mod+">\nphp_flag engine off\n</IfModule>\n")
		if php.PHPDisabled == nil || !*php.PHPDisabled {
			t.Errorf("<IfModule %s> php_flag engine off was not honoured", mod)
		}
	}
}
