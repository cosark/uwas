package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The same domain rule has to hold on every path that can write or load a
// domain: the YAML loader (Validate via ValidateWithDefaults, which also runs
// on reload and the raw editor), the admin JSON Add (ValidateDomain) and the
// admin Update/PATCH (ValidateDomainPartial). A rule enforced by only one of
// them leaves the others able to persist a domain the operator believes is
// restricted, or one the next Load refuses (F16400/R124 class).
//
// Each case builds a domain that breaks exactly one rule and asserts all three
// validators reject it. The few documented, deliberate differences are listed
// as exemptions with their reason; anything else that one validator accepts is
// a gap.

type parityCase struct {
	name   string
	mutate func(*Domain)
	// exempt names the validators that deliberately do not apply the rule.
	exempt map[string]string // "loader" | "add" | "partial" -> reason
}

func parityBase() Domain {
	return Domain{
		Host: "a.example.com",
		Type: "static",
		Root: "/var/www/a.example.com/public_html",
		SSL:  SSLConfig{Mode: "off"},
	}
}

func validateViaLoader(d Domain) error {
	cfg := &Config{Global: GlobalConfig{
		LogLevel: "info", LogFormat: "json",
		Admin:   AdminConfig{Listen: "127.0.0.1:9443"},
		WebRoot: "/var/www",
	}, Domains: []Domain{d}}
	return ValidateWithDefaults(cfg)
}

func TestDomainRulesHoldOnEveryValidatorEntry(t *testing.T) {
	huge := strings.Repeat(".{1000}", 3)
	proxy := func(d *Domain) {
		d.Type = "proxy"
		d.Root = ""
		d.Proxy.Upstreams = []Upstream{{Address: "http://127.0.0.1:3000", Weight: 1}}
	}
	cases := []parityCase{
		{name: "ssl.min_version", mutate: func(d *Domain) { d.SSL.MinVersion = "9.9" }},
		{name: "ssl.mode", mutate: func(d *Domain) { d.SSL.Mode = "sometimes" }},
		{name: "type", mutate: func(d *Domain) { d.Type = "ftp" }},
		{name: "canonical_host", mutate: func(d *Domain) { d.CanonicalHost = "middle" }},
		{name: "ssl.client_auth enum", mutate: func(d *Domain) { d.SSL.ClientAuth = "required" }},
		{name: "ssl.client_auth without ca", mutate: func(d *Domain) { d.SSL.ClientAuth = "require" },
			exempt: map[string]string{"partial": "the CA may already be stored on the domain a PATCH merges into"}},
		{name: "try_files cap", mutate: func(d *Domain) { d.TryFiles = make([]string, MaxTryFiles+1) }},
		{name: "index_files cap", mutate: func(d *Domain) { d.IndexFiles = make([]string, MaxIndexFiles+1) }},
		{name: "php.index_files cap", mutate: func(d *Domain) { d.PHP.IndexFiles = make([]string, MaxIndexFiles+1) }},
		{name: "internal_aliases", mutate: func(d *Domain) { d.InternalAliases = []string{"/etc"} }},
		{name: "proxy upstream ssrf", mutate: func(d *Domain) {
			proxy(d)
			d.Proxy.Upstreams = []Upstream{{Address: "http://169.254.169.254", Weight: 1}}
		}},
		{name: "proxy.algorithm", mutate: func(d *Domain) { proxy(d); d.Proxy.Algorithm = "fastest" }},
		{name: "proxy.canary weight", mutate: func(d *Domain) {
			proxy(d)
			d.Proxy.Canary = CanaryConfig{Enabled: true, Weight: 500, Upstreams: []Upstream{{Address: "http://127.0.0.1:3001"}}}
		}},
		{name: "proxy.mirror percent", mutate: func(d *Domain) {
			proxy(d)
			d.Proxy.Mirror = MirrorConfig{Enabled: true, Percent: 500, Backend: "http://127.0.0.1:3002"}
		}},
		{name: "redirect.target internal host", mutate: func(d *Domain) {
			d.Type = "redirect"
			d.Root = ""
			d.Redirect = RedirectConfig{Target: "http://169.254.169.254/latest", Status: 301}
		}, exempt: map[string]string{
			"loader":  "an operator-written redirect to an internal host is legitimate; the browser, not the server, follows it, and only Add can be reached by writers other than the operator",
			"partial": "Partial validates the MERGED domain, so applying it would block an unrelated PATCH of a YAML-configured internal redirect; non-admins cannot change type or redirect (webAccessFieldChange)",
		}},
		{name: "redirect.status", mutate: func(d *Domain) {
			d.Type = "redirect"
			d.Root = ""
			d.Redirect = RedirectConfig{Target: "https://example.org", Status: 200}
		}},
		{name: "security.rate_limit negative", mutate: func(d *Domain) { d.Security.RateLimit.Requests = -1 }},
		{name: "resources negative", mutate: func(d *Domain) { d.Resources.MemoryMB = -5 }},
		{name: "bandwidth.action", mutate: func(d *Domain) { d.Bandwidth.Action = "Block" }},
		{name: "bandwidth negative limit", mutate: func(d *Domain) { d.Bandwidth.MonthlyLimit = -1 }},
		{name: "rewrites regex", mutate: func(d *Domain) { d.Rewrites = []RewriteRule{{Match: "(", To: "/x"}} }},
		{name: "rewrites flag", mutate: func(d *Domain) { d.Rewrites = []RewriteRule{{Match: "^/a$", To: "-", Flags: []string{"Forbidden"}}} }},
		{name: "rewrites condition", mutate: func(d *Domain) {
			d.Rewrites = []RewriteRule{{Match: "^/a$", To: "-", Flags: []string{"F"}, Conditions: []string{"%{REMOTE_ADDR} !^10\\."}}}
		}},
		{name: "ip_blacklist entry", mutate: func(d *Domain) { d.Security.IPBlacklist = []string{"not-an-ip"} }},
		{name: "maintenance.allowed_ips entry", mutate: func(d *Domain) { d.Maintenance.AllowedIPs = []string{"office"} }},
		{name: "waf unknown rule", mutate: func(d *Domain) {
			d.Security.WAF.Enabled = true
			d.Security.WAF.Rules = []string{"sql_injection", "xxs"}
		}},
		{name: "geo code", mutate: func(d *Domain) { d.Security.GeoBlockCountries = []string{"Turkey"} }},
		{name: "compression algorithm", mutate: func(d *Domain) { d.Compression.Algorithms = []string{"zstd"} }},
		{name: "image_optimization format", mutate: func(d *Domain) {
			d.ImageOptimization.Enabled = true
			d.ImageOptimization.Formats = []string{"jpeg2000"}
		}},
		{name: "location regex", mutate: func(d *Domain) { d.Locations = []LocationConfig{{Match: "~^/admin("}} }},
		{name: "location regex size", mutate: func(d *Domain) { d.Locations = []LocationConfig{{Match: "~^" + huge}} }},
		{name: "cache.ttl negative", mutate: func(d *Domain) { d.Cache.TTL = -1 }},
		{name: "cache rule ttl negative", mutate: func(d *Domain) { d.Cache.Rules = []CacheRule{{Match: "^/a", TTL: -1}} }},
		{name: "cache rule regex", mutate: func(d *Domain) { d.Cache.Rules = []CacheRule{{Match: "*.html"}} }},
		{name: "cache rule regex size", mutate: func(d *Domain) { d.Cache.Rules = []CacheRule{{Match: huge}} }},
		{name: "htaccess.mode", mutate: func(d *Domain) { d.Htaccess.Mode = "on" }},
		{name: "basic_auth without users", mutate: func(d *Domain) { d.BasicAuth = BasicAuthConfig{Enabled: true} }},
		{name: "basic_auth empty password", mutate: func(d *Domain) {
			d.BasicAuth = BasicAuthConfig{Enabled: true, Users: map[string]string{"bob": ""}}
		}},
		{name: "location basic_auth without users", mutate: func(d *Domain) {
			d.Locations = []LocationConfig{{Match: "/admin", BasicAuth: &BasicAuthConfig{Enabled: true}}}
		}},
		{name: "php.env PHP_ADMIN_VALUE", mutate: func(d *Domain) {
			d.Type = "php"
			d.PHP.Env = map[string]string{"PHP_ADMIN_VALUE": "open_basedir=/"}
		}, exempt: map[string]string{"loader": "an operator-written, reviewed PHP_ADMIN_VALUE is allowed (UPGRADING.md); non-admin writers run ValidatePHPEnv themselves (F12000)"}},
	}

	for _, tc := range cases {
		d := parityBase()
		tc.mutate(&d)
		entries := []struct {
			name string
			err  error
		}{
			{"loader", validateViaLoader(d)},
			{"add", ValidateDomain(cloneDomain(d))},
			{"partial", ValidateDomainPartial(cloneDomain(d))},
		}
		for _, e := range entries {
			if reason, ok := tc.exempt[e.name]; ok {
				_ = reason
				continue
			}
			if e.err == nil {
				t.Errorf("%s: the %s validator accepts a domain that breaks the rule", tc.name, e.name)
			}
		}
	}
}

// cloneDomain keeps a validator that mutates its argument from changing the
// domain the next entry is judged on.
func cloneDomain(d Domain) *Domain {
	c := d
	return &c
}

// F16500/F16501 end to end through config.Load, the path uwas.yaml, every
// domains.d file and a reload take: a YAML the admin API would refuse must not
// load, because the server then serves the "protected" content to anyone.
func TestLoadRefusesYAMLThatLeavesAProtectionOff(t *testing.T) {
	const head = "global:\n  log_level: error\n  log_format: text\n  web_root: /var/www\n  admin:\n    listen: 127.0.0.1:9443\ndomains:\n"
	cases := []struct{ name, yaml, want string }{
		{"mistyped users key", `  - host: a.test
    type: static
    root: /var/www/a
    ssl: {mode: "off"}
    basic_auth:
      enabled: true
      usrs: {alice: secret}
`, "basic_auth enabled requires at least one user"},
		{"location basic_auth without users", `  - host: a.test
    type: static
    root: /var/www/a
    ssl: {mode: "off"}
    locations:
      - match: /admin
        basic_auth: {enabled: true}
`, "basic_auth enabled requires at least one user"},
		{"htaccess mode on", `  - host: a.test
    type: static
    root: /var/www/a
    ssl: {mode: "off"}
    htaccess: {mode: "on"}
`, "htaccess.mode"},
	}
	for _, tc := range cases {
		path := filepath.Join(t.TempDir(), "uwas.yaml")
		if err := os.WriteFile(path, []byte(head+tc.yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Load err = %v, want a refusal naming %q", tc.name, err, tc.want)
		}
	}
	// Control: the same shapes written correctly load.
	ok := head + `  - host: a.test
    type: static
    root: /var/www/a
    ssl: {mode: "off"}
    htaccess: {mode: import}
    basic_auth:
      enabled: true
      users: {alice: secret}
`
	path := filepath.Join(t.TempDir(), "uwas.yaml")
	if err := os.WriteFile(path, []byte(ok), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Errorf("a correctly written config must load: %v", err)
	}
}
