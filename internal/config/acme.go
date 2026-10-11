package config

// ACMEConfig configures automatic TLS via ACME (Let's Encrypt etc.).
type ACMEConfig struct {
	Email              string            `yaml:"email"`
	CAURL              string            `yaml:"ca_url"`
	Storage            string            `yaml:"storage"`
	DNSProvider        string            `yaml:"dns_provider"`
	DNSCredentials     map[string]string `yaml:"dns_credentials"`
	OnDemand           bool              `yaml:"on_demand"`
	OnDemandAsk        string            `yaml:"on_demand_ask"`
	SelfSignedValidity Duration          `yaml:"self_signed_validity"` // validity period for self-signed fallback certs (default 24h)
}

// acmeDNSProviders are the DNS providers the ACME manager can build a DNS-01
// solver for. internal/tls matches the name exactly and only logs a warning for
// any other value, so a misspelt global.acme.dns_provider left wildcard names
// with no way to be issued (F13800). Config cannot import internal/tls, so it
// carries the list; a test in internal/server keeps the two in step.
var acmeDNSProviders = []string{"cloudflare", "digitalocean", "hetzner", "route53"}

// ACMEDNSProviderNames returns the provider names global.acme.dns_provider may
// take.
func ACMEDNSProviderNames() []string {
	return append([]string(nil), acmeDNSProviders...)
}

// KnownACMEDNSProvider reports whether name is a DNS provider the ACME manager
// recognises. The match is exact, as in the manager.
func KnownACMEDNSProvider(name string) bool {
	for _, n := range acmeDNSProviders {
		if name == n {
			return true
		}
	}
	return false
}

// normalizeACMECredentials copies the AWS-style Route53 credential names the
// dashboard and the settings API write (access_key_id, secret_access_key) to
// the names the ACME manager and the DNS handlers read (access_key, secret_key).
// Without this a Route53 provider configured from the panel was never built
// (F13801). The original keys stay, so the panel keeps showing what it saved,
// and a canonical key that is already set wins.
func normalizeACMECredentials(creds map[string]string) {
	for alias, canonical := range map[string]string{
		"access_key_id":     "access_key",
		"secret_access_key": "secret_key",
	} {
		if v := creds[alias]; v != "" && creds[canonical] == "" {
			creds[canonical] = v
		}
	}
}
