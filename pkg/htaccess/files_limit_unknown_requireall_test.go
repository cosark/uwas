package htaccess

import (
	"net"
	"testing"
)

// A <Limit>/<LimitExcept> section inside <Files>/<FilesMatch> must keep its
// denial: the per-file check has no request method (F5500).
func TestFilesMatchLimitDenies(t *testing.T) {
	ip := net.ParseIP("203.0.113.9")
	rs := conditionalRules(t, "<Files wp-config.php>\n<Limit GET POST>\nRequire all denied\n</Limit>\n</Files>\n")
	if !FilesMatchDeniesFor(rs, "wp-config.php", ip) {
		t.Error("wp-config.php not denied by <Limit GET POST>")
	}
	if FilesMatchDeniesFor(rs, "index.php", ip) {
		t.Error("index.php denied")
	}
	if !FilesMatchDeniesForMethod(rs, "wp-config.php", ip, "GET") || FilesMatchDeniesForMethod(rs, "wp-config.php", ip, "DELETE") {
		t.Error("method-aware check: GET must deny, DELETE must not")
	}
	ex := conditionalRules(t, "<FilesMatch \"\\.sql$\">\n<LimitExcept GET POST>\nRequire all denied\n</LimitExcept>\n</FilesMatch>\n")
	if FilesMatchDeniesFor(ex, "dump.sql", ip) {
		t.Error("<LimitExcept GET POST> deny must not block GET/POST")
	}
	if !FilesMatchDeniesForMethod(ex, "dump.sql", ip, "DELETE") {
		t.Error("<LimitExcept GET POST> deny not applied to DELETE")
	}
}

// A <FilesMatch> deny inside a section whose condition cannot be decided is
// kept, while one that does not deny stays inert (F5501).
func TestFilesMatchInUndecidableSectionDenies(t *testing.T) {
	ip := net.ParseIP("203.0.113.9")
	deny := "<FilesMatch \"\\.sql$\">\nRequire all denied\n</FilesMatch>\n"
	for name, src := range map[string]string{
		"If":     "<If \"%{HTTPS} == 'on'\">\n" + deny + "</If>\n",
		"Else":   "<If \"%{HTTPS} == 'on'\">\nHeader set X y\n</If>\n<Else>\n" + deny + "</Else>\n",
		"nested": "<If \"%{HTTPS} == 'on'\">\n<IfModule mod_headers.c>\n" + deny + "</IfModule>\n</If>\n",
	} {
		rs := conditionalRules(t, src)
		if !FilesMatchDeniesFor(rs, "dump.sql", ip) {
			t.Errorf("%s: dump.sql not denied", name)
		}
		if FilesMatchDeniesFor(rs, "index.html", ip) {
			t.Errorf("%s: index.html denied", name)
		}
	}
	allow := conditionalRules(t, "<If \"%{HTTPS} == 'on'\">\n<FilesMatch \"\\.sql$\">\nRequire ip 203.0.113.0/24\n</FilesMatch>\n</If>\n")
	if FilesMatchDeniesFor(allow, "dump.sql", ip) {
		t.Error("allowlisted client denied")
	}
	if !FilesMatchDeniesFor(allow, "dump.sql", net.ParseIP("198.51.100.1")) {
		t.Error("client outside the allowlist not denied")
	}
	harmless := conditionalRules(t, "<If \"%{HTTPS} == 'on'\">\nHeader set X y\n</If>\n")
	if harmless.AccessFor(ip) != AccessUnset {
		t.Error("harmless <If> changed access")
	}
}

// <RequireAll> combining an IP condition with authentication cannot be
// satisfied on the IP alone: credentials are not verified here (F5502).
func TestRequireAllWithAuthDoesNotGrantOnIP(t *testing.T) {
	in, out := net.ParseIP("203.0.113.9"), net.ParseIP("198.51.100.1")
	rs := conditionalRules(t, "<RequireAll>\nRequire ip 203.0.113.0/24\nRequire valid-user\n</RequireAll>\n")
	for _, ip := range []net.IP{in, out} {
		if got := rs.AccessFor(ip); got != AccessDenied {
			t.Errorf("%v: got %v, want denied", ip, got)
		}
	}
	nested := conditionalRules(t, "<RequireAll>\nRequire ip 203.0.113.0/24\n<IfModule mod_authz_core.c>\nRequire user alice\n</IfModule>\n</RequireAll>\n")
	if got := nested.AccessFor(in); got != AccessDenied {
		t.Errorf("auth Require inside IfModule: got %v, want denied", got)
	}
	any := conditionalRules(t, "<RequireAny>\nRequire ip 203.0.113.0/24\nRequire valid-user\n</RequireAny>\n")
	if got := any.AccessFor(in); got != AccessGranted {
		t.Errorf("<RequireAny> ip branch: got %v, want granted", got)
	}
	plain := conditionalRules(t, "<RequireAll>\nRequire ip 203.0.113.0/24\n</RequireAll>\n")
	if plain.AccessFor(in) != AccessGranted || plain.AccessFor(out) != AccessDenied {
		t.Error("ip-only RequireAll regressed")
	}
}
