package migrate

import (
	"strings"
	"testing"
)

// F8602-F8604: nginx import. A one-line `location ... { ...; }` block leaves
// the parser "inside" it, so the following server directives (root, ssl_*)
// and locations are swallowed; `location /private/ { deny all; }` is not
// migrated at all (the path becomes public); and the usual :80 redirect +
// :443 server pair becomes two domains with one host.
func TestNginxMigrationOneLineLocationsDenyAllAndHTTPSPair(t *testing.T) {
	parse := func(src string) []NginxConfig {
		cfgs, err := ParseNginx(strings.NewReader(src))
		if err != nil {
			t.Fatalf("invalid proof: %v", err)
		}
		return cfgs
	}
	// Control: multi-line location blocks parse and keep the directives after.
	ctl := parse("server {\nserver_name a.test;\nlocation /x/ {\nroot /srv/x;\n}\nroot /var/www/a;\nssl_certificate /c;\n}\n")
	if len(ctl) != 1 || ctl[0].Root != "/var/www/a" || ctl[0].SSLCert != "/c" {
		t.Fatalf("invalid proof: control %+v", ctl)
	}

	bad := 0
	// F8602
	one := parse("server {\nserver_name a.test;\nlocation = /favicon.ico { access_log off; }\nroot /var/www/a;\nssl_certificate /c;\nssl_certificate_key /k;\nlocation /api/ {\nproxy_pass http://127.0.0.1:3000;\n}\n}\n")
	t.Logf("EXPECTED: root /var/www/a, cert /c, 2 locations")
	t.Logf("ACTUAL: root %q cert %q locations %d", one[0].Root, one[0].SSLCert, len(one[0].Locations))
	if one[0].Root != "/var/www/a" || one[0].SSLCert != "/c" || len(one[0].Locations) != 2 {
		bad++
	}
	// F8603
	deny := parse("server {\nserver_name a.test;\nroot /var/www/a;\nlocation /private/ {\ndeny all;\n}\n}\n")
	doms := ConvertToUWAS(deny)
	t.Logf("EXPECTED: blocked_paths contains /private/")
	t.Logf("ACTUAL: blocked_paths %v", doms[0].Security.BlockedPaths)
	if len(doms[0].Security.BlockedPaths) != 1 {
		bad++
	}
	// The YAML carries the blocked path too.
	yml, err := NginxToYAML(strings.NewReader("server {\nserver_name a.test;\nroot /var/www/a;\nlocation ^~ /private/ {\ndeny all;\n}\n}\n"))
	if err != nil || !strings.Contains(yml, "blocked_paths:") || !strings.Contains(yml, "/private/") {
		t.Errorf("YAML lacks blocked_paths (err=%v):\n%s", err, yml)
		bad++
	}
	// F8604
	pair := parse("server {\nlisten 80;\nserver_name b.test;\nreturn 301 https://b.test$request_uri;\n}\nserver {\nlisten 443 ssl;\nserver_name b.test;\nroot /var/www/b;\nssl_certificate /c;\nssl_certificate_key /k;\n}\n")
	pd := ConvertToUWAS(pair)
	hosts := 0
	for _, d := range pd {
		if d.Host == "b.test" {
			hosts++
		}
	}
	t.Logf("EXPECTED: one domain for b.test")
	t.Logf("ACTUAL: %d domains for b.test", hosts)
	if hosts != 1 {
		bad++
	}
	if bad > 0 {
		t.Fatal("F8602-F8604 regression")
	}
}
