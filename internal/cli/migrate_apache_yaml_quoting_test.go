package cli

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// F8310: values the Apache converter copies into YAML must read back exactly,
// and plain values must keep the unquoted output form.
func TestConvertApacheToYAMLQuotesSpecialValues(t *testing.T) {
	odd := []string{"/var/www/site #1", "/srv/a: b", "/srv/*glob", `/srv/it's`, "/srv/ok\\path", "@home", "true", "123"}
	for _, v := range odd {
		out := convertApacheToYAML([]apacheVHost{{
			serverName:   "example.com",
			documentRoot: v,
			sslCertFile:  v + ".crt",
			sslKeyFile:   v + ".key",
			proxyPass:    []apacheProxy{{path: "/", target: v}},
		}})
		var doc struct {
			Domains []struct {
				Host string `yaml:"host"`
				Root string `yaml:"root"`
				SSL  struct {
					Cert string `yaml:"cert"`
					Key  string `yaml:"key"`
				} `yaml:"ssl"`
				Proxy struct {
					Upstreams []struct {
						Address string `yaml:"address"`
					} `yaml:"upstreams"`
				} `yaml:"proxy"`
			} `yaml:"domains"`
		}
		if err := yaml.Unmarshal([]byte(out), &doc); err != nil || len(doc.Domains) != 1 {
			t.Errorf("%q: unparsable output (%v):\n%s", v, err, out)
			continue
		}
		d := doc.Domains[0]
		if d.Host != "example.com" || d.Root != v || d.SSL.Cert != v+".crt" || d.SSL.Key != v+".key" ||
			len(d.Proxy.Upstreams) != 1 || d.Proxy.Upstreams[0].Address != v {
			t.Errorf("%q: values changed: %+v", v, d)
		}
	}

	// Control: ordinary values stay plain, as before.
	out := convertApacheToYAML([]apacheVHost{{serverName: "example.com", documentRoot: "/var/www/site"}})
	for _, want := range []string{"  - host: example.com\n", "    root: /var/www/site\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("plain output changed, missing %q in:\n%s", want, out)
		}
	}
}
