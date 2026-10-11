package cli

import (
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
	"gopkg.in/yaml.v3"
)

// See migrate.TestNginxYAMLOnlyUsesKnownConfigKeys: config.Load is not strict,
// so a mistyped key in the generated YAML would silently vanish on load.
func TestApacheYAMLOnlyUsesKnownConfigKeys(t *testing.T) {
	out := convertApacheToYAML([]apacheVHost{
		{serverName: "static.example.com", documentRoot: "/var/www/s", aliases: []string{"www.static.example.com"},
			sslEngine: true, sslCertFile: "/etc/ssl/c.pem", sslKeyFile: "/etc/ssl/k.pem", listen: "*:443"},
		{serverName: "proxy.example.com", listen: "*:80",
			proxyPass: []apacheProxy{{path: "/", target: "http://127.0.0.1:3000"}},
			locations: []apacheProxy{{path: "/api", target: "http://127.0.0.1:4000/"}}},
	})

	var cfg config.Config
	dec := yaml.NewDecoder(strings.NewReader(out))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		t.Fatalf("emitted YAML has a key config.Config does not know: %v\n%s", err, out)
	}
	if len(cfg.Domains) != 2 {
		t.Fatalf("decoded %d domains, want 2\n%s", len(cfg.Domains), out)
	}
	if d := cfg.Domains[0]; d.Root != "/var/www/s" || d.SSL.Mode != "manual" || d.SSL.Cert != "/etc/ssl/c.pem" || d.SSL.Key != "/etc/ssl/k.pem" {
		t.Errorf("static domain lost values: %+v", d)
	}
	d := cfg.Domains[1]
	if len(d.Proxy.Upstreams) != 1 || len(d.Locations) != 1 || d.Locations[0].ProxyPass != "http://127.0.0.1:4000" || !d.Locations[0].StripPrefix {
		t.Errorf("proxy domain lost values: %+v", d)
	}
}
