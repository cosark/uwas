package migrate

import (
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
	"gopkg.in/yaml.v3"
)

// config.Load decodes YAML without KnownFields, so a key the migrator mistypes
// would be dropped silently on load and the migrated site would run without the
// setting. Decode the emitter's output strictly to catch that here.
func TestNginxYAMLOnlyUsesKnownConfigKeys(t *testing.T) {
	domains := []config.Domain{
		{Host: "static.example.com", Type: "static", Root: "/var/www/s", Aliases: []string{"www.static.example.com"},
			IndexFiles: []string{"index.html"}, SPAMode: true, TryFiles: []string{"$uri", "/index.html"},
			SSL:      config.SSLConfig{Mode: "manual", Cert: "/etc/ssl/c.pem", Key: "/etc/ssl/k.pem"},
			Security: config.SecurityConfig{BlockedPaths: []string{"/private"}}},
		{Host: "php.example.com", Type: "php", Root: "/var/www/p", SSL: config.SSLConfig{Mode: "auto"},
			PHP: config.PHPConfig{FPMAddress: "unix:/run/php/fpm.sock", IndexFiles: []string{"index.php"}}},
		{Host: "proxy.example.com", Type: "proxy", Proxy: config.ProxyConfig{Upstreams: []config.Upstream{{Address: "http://127.0.0.1:3000"}}}},
		{Host: "redir.example.com", Type: "redirect", Redirect: config.RedirectConfig{Target: "https://example.com", Status: 301, PreservePath: true}},
	}
	out := domainsToYAML(domains)

	var cfg config.Config
	dec := yaml.NewDecoder(strings.NewReader(out))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		t.Fatalf("emitted YAML has a key config.Config does not know: %v\n%s", err, out)
	}
	if len(cfg.Domains) != len(domains) {
		t.Fatalf("decoded %d domains, want %d", len(cfg.Domains), len(domains))
	}
	// A key that is known but misplaced decodes without error yet loses its
	// value; check the values survived.
	got := cfg.Domains[0]
	if got.Root != "/var/www/s" || !got.SPAMode || got.SSL.Cert != "/etc/ssl/c.pem" ||
		len(got.Security.BlockedPaths) != 1 || len(got.TryFiles) != 2 {
		t.Errorf("static domain lost values on decode: %+v", got)
	}
	if p := cfg.Domains[1].PHP; p.FPMAddress != "unix:/run/php/fpm.sock" || len(p.IndexFiles) != 1 {
		t.Errorf("php block lost values: %+v", p)
	}
	if u := cfg.Domains[2].Proxy.Upstreams; len(u) != 1 || u[0].Address != "http://127.0.0.1:3000" {
		t.Errorf("proxy upstreams lost: %+v", u)
	}
	if r := cfg.Domains[3].Redirect; r.Target != "https://example.com" || r.Status != 301 || !r.PreservePath {
		t.Errorf("redirect block lost values: %+v", r)
	}
}
