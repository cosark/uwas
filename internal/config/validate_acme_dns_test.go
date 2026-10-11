package config

import (
	"strings"
	"testing"
)

// F13800: the ACME manager matches global.acme.dns_provider exactly and only
// logs a warning for anything else, so a misspelt provider silently left
// wildcard names without a DNS-01 solver.
func TestValidateRejectsUnknownACMEDNSProvider(t *testing.T) {
	for _, p := range []string{"", "cloudflare", "digitalocean", "hetzner", "route53"} {
		cfg := &Config{}
		cfg.Global.ACME.DNSProvider = p
		if err := ValidateWithDefaults(cfg); err != nil {
			t.Errorf("dns_provider %q rejected: %v", p, err)
		}
	}
	for _, p := range []string{"Cloudflare", "cloudflare ", " cloudflare", "cloudfare", "route-53", "aws", "gandi"} {
		cfg := &Config{}
		cfg.Global.ACME.DNSProvider = p
		err := ValidateWithDefaults(cfg)
		if err == nil || !strings.Contains(err.Error(), "global.acme.dns_provider") {
			t.Errorf("dns_provider %q: err = %v, want a global.acme.dns_provider error", p, err)
		}
	}
}

// F13801: the dashboard writes Route53 credentials as access_key_id /
// secret_access_key, the ACME manager and DNS handlers read access_key /
// secret_key.
func TestApplyDefaultsMapsRoute53CredentialAliases(t *testing.T) {
	cfg := &Config{}
	cfg.Global.ACME.DNSProvider = "route53"
	cfg.Global.ACME.DNSCredentials = map[string]string{"access_key_id": "AK", "secret_access_key": "SK", "region": "eu-west-1"}
	if err := ValidateWithDefaults(cfg); err != nil {
		t.Fatal(err)
	}
	c := cfg.Global.ACME.DNSCredentials
	if c["access_key"] != "AK" || c["secret_key"] != "SK" {
		t.Errorf("canonical keys not set: %v", c)
	}
	if c["access_key_id"] != "AK" || c["secret_access_key"] != "SK" || c["region"] != "eu-west-1" {
		t.Errorf("panel keys must stay as saved: %v", c)
	}

	// A canonical key that is already set wins over the alias.
	cfg = &Config{}
	cfg.Global.ACME.DNSCredentials = map[string]string{"access_key": "CANON", "access_key_id": "ALIAS", "secret_key": "S"}
	applyDefaults(cfg)
	if got := cfg.Global.ACME.DNSCredentials["access_key"]; got != "CANON" {
		t.Errorf("access_key = %q, want CANON", got)
	}

	// An empty alias adds nothing, and a nil map is left alone.
	cfg = &Config{}
	cfg.Global.ACME.DNSCredentials = map[string]string{"access_key_id": ""}
	applyDefaults(cfg)
	if _, ok := cfg.Global.ACME.DNSCredentials["access_key"]; ok {
		t.Errorf("empty alias must not create access_key: %v", cfg.Global.ACME.DNSCredentials)
	}
	cfg = &Config{}
	applyDefaults(cfg)
	if cfg.Global.ACME.DNSCredentials != nil {
		t.Errorf("nil credentials map was replaced: %v", cfg.Global.ACME.DNSCredentials)
	}
}
