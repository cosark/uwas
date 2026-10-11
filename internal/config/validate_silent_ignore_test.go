package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func silentIgnoreDomain() Domain {
	return Domain{Host: "x.test", Type: "static", Root: "/var/www/x", SSL: SSLConfig{Mode: "off"}}
}

// F13500/F13501: ssl.client_auth is compared exactly, so any other spelling
// meant "none", and require/request without a CA was skipped. Both served
// anonymous clients while the operator believed mutual TLS was on.
func TestSSLClientAuthRejectsSpellingsThatDisableMutualTLS(t *testing.T) {
	cases := []struct {
		auth, ca string
		partial  bool
		ok       bool
	}{
		{"", "", false, true},
		{"none", "", false, true},
		{"none", "/etc/ssl/ca.pem", false, true},
		{"request", "/etc/ssl/ca.pem", false, true},
		{"require", "/etc/ssl/ca.pem", false, true},
		{"required", "/etc/ssl/ca.pem", false, false},
		{"Require", "/etc/ssl/ca.pem", false, false},
		{"mutual", "/etc/ssl/ca.pem", false, false},
		{"verify", "", false, false},
		{"require", "", false, false}, // no CA: cannot be enforced
		{"request", "", false, false},
		// A partial update names only the fields it changes; the CA may
		// already be on the stored domain.
		{"require", "", true, true},
		{"required", "", true, false},
	}
	for _, c := range cases {
		d := silentIgnoreDomain()
		d.SSL.ClientAuth, d.SSL.ClientCA = c.auth, c.ca
		var err error
		if c.partial {
			err = ValidateDomainPartial(&d)
		} else {
			err = ValidateDomain(&d)
		}
		if (err == nil) != c.ok {
			t.Errorf("client_auth=%q client_ca=%q partial=%v: err=%v, want ok=%v", c.auth, c.ca, c.partial, err, c.ok)
		}
	}
}

// F13502: an unknown security.waf.rules name is dropped by the WAF, so a typo
// next to valid entries silently removes that family's checks.
func TestWAFRulesRejectUnknownFamilyNames(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		rules   []string
		ok      bool
	}{
		{"all families", true, []string{"sql_injection", "xss", "path_traversal", "shell_injection", "php", "file_probe"}, true},
		{"case and spaces as the WAF reads them", true, []string{"SQL_Injection", " xss "}, true},
		{"empty list means every family", true, nil, true},
		{"typo", true, []string{"sql_injection", "xxs"}, false},
		{"legacy name", true, []string{"sqli"}, false},
		{"typo with the WAF off is left alone", false, []string{"xxs"}, true},
	} {
		d := silentIgnoreDomain()
		d.Security.WAF = WAFConfig{Enabled: tc.enabled, Rules: tc.rules}
		err := ValidateDomain(&d)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

// F13503: the geo guard compares two-character codes; anything else never
// matches, so a block list entry blocks nothing.
func TestGeoCountryEntriesMustBeTwoCharacterCodes(t *testing.T) {
	for _, code := range []string{"TR", "tr", "T1", "XX"} {
		d := silentIgnoreDomain()
		d.Security.GeoBlockCountries = []string{code}
		d.Security.GeoAllowCountries = []string{code}
		if err := ValidateDomain(&d); err != nil {
			t.Errorf("%q: %v", code, err)
		}
	}
	for _, code := range []string{"Turkey", "TUR", " TR", "T R", "T", ""} {
		for _, field := range []string{"geo_block_countries", "geo_allow_countries"} {
			d := silentIgnoreDomain()
			if field == "geo_block_countries" {
				d.Security.GeoBlockCountries = []string{code}
			} else {
				d.Security.GeoAllowCountries = []string{code}
			}
			err := ValidateDomain(&d)
			if err == nil || !strings.Contains(err.Error(), field) {
				t.Errorf("%s %q: err=%v, want a %s error", field, code, err, field)
			}
		}
	}
}

// F13504: the loader decodes non-strictly, so a misspelt key anywhere was
// dropped without a word and the setting it stood for was silently absent.
func TestLoadWarnsAboutKeysTheSchemaDoesNotHave(t *testing.T) {
	root, web := t.TempDir(), t.TempDir()
	write := func(dir, name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	main := func(extra string) string {
		return fmt.Sprintf("global:\n  web_root: %s\ndomains:\n  - host: a.test\n    type: static\n    root: %s\n    ssl:\n      mode: \"off\"\n%s", web, root, extra)
	}

	// Control: a correct config loads and reports nothing.
	clean, err := Load(write(t.TempDir(), "uwas.yaml", main("    security:\n      ip_whitelist: [\"10.0.0.0/8\"]\n")))
	if err != nil {
		t.Fatal(err)
	}
	if len(clean.Warnings) != 0 {
		t.Errorf("clean config reported %v", clean.Warnings)
	}

	dir := t.TempDir()
	path := write(dir, "uwas.yaml", main("    security:\n      ip_whitlist: [\"10.0.0.0/8\"]\n"))
	write(dir, "domains.d/nohost.yaml", fmt.Sprintf("hosts: b.test\ntype: static\nroot: %s\nssl:\n  mode: \"off\"\n", root))
	write(dir, "domains.d/typo.yaml", fmt.Sprintf("host: c.test\ntype: static\nroot: %s\nssl:\n  mode: \"off\"\nsecurty:\n  waf: {enabled: true}\n", root))
	write(dir, "domains.d/list.yaml", fmt.Sprintf("domains:\n  - host: d.test\n    type: static\n    root: %s\n    ssl: {mode: \"off\"}\n    cach: {enabled: true}\n", root))
	write(dir, "domains.d/empty.yaml", "# nothing here\n")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	joined := strings.Join(cfg.Warnings, "\n")
	for _, want := range []string{"ip_whitlist", "nohost.yaml", "securty", "cach"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings do not mention %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "empty.yaml") {
		t.Errorf("an empty file is not a warning:\n%s", joined)
	}
	// The loaded config itself is unchanged by the report.
	if got := len(cfg.Domains); got != 3 { // a, c, d (nohost skipped)
		t.Errorf("domains loaded = %d, want 3", got)
	}
}

// The shipped example must not trip the unknown-key report, or every operator
// who copies it would see a warning on a correct file.
func TestExampleConfigHasNoUnknownKeys(t *testing.T) {
	b, err := os.ReadFile("../../uwas.example.yaml")
	if err != nil {
		t.Skip(err)
	}
	for _, w := range unknownKeys("uwas.example.yaml", []byte(expandEnvVars(string(b))), &Config{}) {
		t.Error(w)
	}
}
