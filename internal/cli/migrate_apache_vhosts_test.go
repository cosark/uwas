package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

// F8600: `uwas migrate apache` loses ServerAlias, keeps the ":443" of
// `ServerName host:443` as part of the host, and turns the ordinary
// <VirtualHost *:80> + <VirtualHost *:443> pair of one site into two domains
// with the same host, which config validation rejects.
func TestApacheMigrationMergesVHostsAliasesAndPorts(t *testing.T) {
	migrate := func(src string) (*config.Config, error) {
		dir := t.TempDir()
		crt := filepath.Join(dir, "c.pem")
		os.WriteFile(crt, []byte("x"), 0o600)
		src = strings.ReplaceAll(src, "CRT", crt)
		conf := filepath.Join(dir, "site.conf")
		os.WriteFile(conf, []byte(src), 0o600)
		f, err := os.Open(conf)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		out := convertApacheToYAML(parseApacheConfig(f))
		p := filepath.Join(dir, "uwas.yaml")
		os.WriteFile(p, []byte(out), 0o600)
		return config.Load(p)
	}

	// Control: one plain vhost converts into a loadable config.
	ctl, err := migrate("<VirtualHost *:80>\nServerName plain.test\nDocumentRoot /var/www/plain\n</VirtualHost>\n")
	if err != nil || len(ctl.Domains) != 1 || ctl.Domains[0].Host != "plain.test" {
		t.Fatalf("invalid proof: control cfg=%v err=%v", ctl, err)
	}

	bad := 0
	// 1. ServerAlias must survive as aliases.
	c1, err := migrate("<VirtualHost *:80>\nServerName a.test\nServerAlias www.a.test shop.a.test\nDocumentRoot /var/www/a\n</VirtualHost>\n")
	got := []string(nil)
	if err == nil && len(c1.Domains) == 1 {
		got = c1.Domains[0].Aliases
	}
	t.Logf("EXPECTED: aliases [www.a.test shop.a.test]")
	t.Logf("ACTUAL: aliases %v err=%v", got, err)
	if len(got) != 2 {
		bad++
	}
	// 2. ServerName host:port keeps only the host.
	c2, err := migrate("<VirtualHost *:443>\nServerName b.test:443\nDocumentRoot /var/www/b\nSSLEngine on\nSSLCertificateFile CRT\nSSLCertificateKeyFile CRT\n</VirtualHost>\n")
	host := ""
	if err == nil && len(c2.Domains) == 1 {
		host = c2.Domains[0].Host
	}
	t.Logf("EXPECTED: host b.test")
	t.Logf("ACTUAL: host %q err=%v", host, err)
	if host != "b.test" {
		bad++
	}
	// 3. The :80 and :443 vhosts of one site become one domain.
	c3, err := migrate("<VirtualHost *:80>\nServerName c.test\nDocumentRoot /var/www/c\n</VirtualHost>\n<VirtualHost *:443>\nServerName c.test\nDocumentRoot /var/www/c\nSSLEngine on\nSSLCertificateFile CRT\nSSLCertificateKeyFile CRT\n</VirtualHost>\n")
	n, mode := 0, ""
	if err == nil {
		n = len(c3.Domains)
		if n == 1 {
			mode = c3.Domains[0].SSL.Mode
		}
	}
	t.Logf("EXPECTED: 1 domain with ssl.mode manual")
	t.Logf("ACTUAL: %d domains mode=%q err=%v", n, mode, err)
	if n != 1 || mode != "manual" {
		bad++
	}
	if bad > 0 {
		t.Fatal("F8600/F8601 regression")
	}

}

// F8601: `ProxyPass /static !` (exclusion) becomes an upstream with address
// "!" and a path-scoped `ProxyPass /api http://backend` turns the WHOLE site
// into a proxy, so the static files of the vhost are never served again.
func TestApacheMigrationProxyPassExclusionAndPathScope(t *testing.T) {
	migrate := func(src string) *config.Config {
		dir := t.TempDir()
		conf := filepath.Join(dir, "site.conf")
		os.WriteFile(conf, []byte(src), 0o600)
		f, err := os.Open(conf)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		p := filepath.Join(dir, "uwas.yaml")
		os.WriteFile(p, []byte(convertApacheToYAML(parseApacheConfig(f))), 0o600)
		cfg, err := config.Load(p)
		if err != nil {
			t.Fatalf("invalid proof: load: %v", err)
		}
		if len(cfg.Domains) != 1 {
			t.Fatalf("invalid proof: %d domains", len(cfg.Domains))
		}
		return cfg
	}

	// Control: a whole-site ProxyPass / stays a proxy domain.
	ctl := migrate("<VirtualHost *:80>\nServerName ctl.test\nProxyPass / http://127.0.0.1:3000/\n</VirtualHost>\n")
	if ctl.Domains[0].Type != "proxy" || len(ctl.Domains[0].Proxy.Upstreams) != 1 {
		t.Fatalf("invalid proof: control %+v", ctl.Domains[0])
	}

	bad := 0
	ex := migrate("<VirtualHost *:80>\nServerName d.test\nDocumentRoot /var/www/d\nProxyPass /static !\nProxyPass / http://127.0.0.1:3000/\n</VirtualHost>\n")
	for _, u := range ex.Domains[0].Proxy.Upstreams {
		t.Logf("ACTUAL: upstream %q", u.Address)
		if u.Address == "!" {
			bad++
		}
	}
	t.Logf("EXPECTED: no upstream \"!\"")

	sc := migrate("<VirtualHost *:80>\nServerName e.test\nDocumentRoot /var/www/e\nProxyPass /api http://127.0.0.1:3000/x\n</VirtualHost>\n")
	d := sc.Domains[0]
	t.Logf("EXPECTED: type static with location /api -> http://127.0.0.1:3000/x")
	t.Logf("ACTUAL: type=%q locations=%d upstreams=%d", d.Type, len(d.Locations), len(d.Proxy.Upstreams))
	if d.Type == "proxy" || len(d.Locations) != 1 || d.Locations[0].ProxyPass == "" {
		bad++
	}
	if bad > 0 {
		t.Fatal("F8600/F8601 regression")
	}

}
