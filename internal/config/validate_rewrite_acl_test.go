package config

import (
	"strings"
	"testing"
)

// A "conditions:" entry the converter cannot translate is dropped, which made
// the rule fire for every request; validation must refuse it (F6600).
func TestValidateDomainRejectsUnsupportedRewriteCondition(t *testing.T) {
	mk := func(match string, conds ...string) *Domain {
		return &Domain{Host: "example.com", Type: "static", Root: "/tmp",
			Rewrites: []RewriteRule{{Match: match, To: "-", Flags: []string{"F"}, Conditions: conds}}}
	}
	for _, c := range []string{"is_file", "!is_file", "-f", "!-f", "is_dir", "!is_dir", "-d", "!-d"} {
		if err := ValidateDomain(mk("^/p/", c)); err != nil {
			t.Errorf("supported condition %q rejected: %v", c, err)
		}
	}
	err := ValidateDomain(mk("^/p/", "!-f", "%{REMOTE_ADDR} !^10\\."))
	if err == nil || !strings.Contains(err.Error(), "rewrites[0].conditions[1]") {
		t.Errorf("unsupported condition: err=%v, want a rewrites[0].conditions[1] error", err)
	}
	if err := ValidateDomain(mk("^(?!index\\.php$).*\\.php$")); err != nil {
		t.Errorf("leading negative lookahead the engine supports was refused: %v", err)
	}
	if err := ValidateDomain(mk("^/a(")); err == nil || !strings.Contains(err.Error(), "invalid regex in match") {
		t.Errorf("uncompilable match: err=%v", err)
	}
}

// An ip_blacklist entry the guard cannot parse is skipped, so the address it
// was meant to block gets through; validation must refuse it (F6601).
func TestValidateDomainRejectsMalformedIPBlacklistEntry(t *testing.T) {
	cases := []struct {
		entry   string
		wantErr bool
	}{
		{"203.0.113.9", false},
		{"203.0.113.0/24", false},
		{"2001:db8::1", false},
		{"2001:db8::/32", false},
		{"203.0.113.9 ", true},
		{" 203.0.113.9", true},
		{"203.0.113.0/33", true},
		{"203.0.113", true},
		{"", true},
	}
	for _, c := range cases {
		d := &Domain{Host: "example.com", Type: "static", Root: "/tmp"}
		d.Security.IPBlacklist = []string{c.entry}
		err := ValidateDomain(d)
		if (err != nil) != c.wantErr {
			t.Errorf("entry %q: err=%v, wantErr=%v", c.entry, err, c.wantErr)
		}
		if err != nil && !strings.Contains(err.Error(), "ip_blacklist[0]") {
			t.Errorf("entry %q: error %q does not name the field", c.entry, err)
		}
	}
}

// An unknown flag token is ignored by the engine, so a typo such as
// "Forbidden" for [F] left a guard rule that forbade nothing (F6602).
func TestValidateDomainRejectsUnknownRewriteFlag(t *testing.T) {
	mk := func(flags ...string) *Domain {
		return &Domain{Host: "example.com", Type: "static", Root: "/tmp",
			Rewrites: []RewriteRule{{Match: "^/p/", To: "-", Flags: flags}}}
	}
	for _, ok := range [][]string{{"F"}, {"f"}, {"L", "QSA"}, {"L,NC"}, {"[R=301,L]"}, {"S=2"}, {"E=VAR:1"}, {"END"}} {
		if err := ValidateDomain(mk(ok...)); err != nil {
			t.Errorf("flags %v rejected: %v", ok, err)
		}
	}
	for _, bad := range [][]string{{"Forbidden"}, {"L", "Gone"}, {"403"}} {
		err := ValidateDomain(mk(bad...))
		if err == nil || !strings.Contains(err.Error(), "rewrites[0].flags[") {
			t.Errorf("flags %v: err=%v, want a rewrites[0].flags error", bad, err)
		}
	}
}
