package server

import (
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
	uwastls "github.com/uwaserver/uwas/internal/tls"
	"github.com/uwaserver/uwas/internal/webhook"
)

// config validation names the DNS providers global.acme.dns_provider may take
// (F13800), and config cannot import internal/tls, so it carries its own list.
// Every name it accepts must be one the ACME manager can build.
func TestConfigACMEDNSProvidersMatchTheACMEManager(t *testing.T) {
	creds := map[string]string{"api_token": "t", "access_key": "a", "secret_key": "s"}
	for _, name := range config.ACMEDNSProviderNames() {
		if _, err := uwastls.NewACMEDNSProvider(name, creds, nil); err != nil {
			t.Errorf("config accepts dns_provider %q but the ACME manager cannot build it: %v", name, err)
		}
	}
	if _, err := uwastls.NewACMEDNSProvider("no-such-provider", creds, nil); err == nil || !strings.Contains(err.Error(), "unknown DNS provider") {
		t.Fatalf("probe name was not rejected as unknown: %v", err)
	}
}

// F13801: Route53 credentials as the dashboard saves them must reach the ACME
// manager under the names it reads.
func TestPanelRoute53CredentialsBuildTheACMEProvider(t *testing.T) {
	cfg := &config.Config{}
	cfg.Global.ACME.Email = "ops@example.com"
	cfg.Global.ACME.DNSProvider = "route53"
	cfg.Global.ACME.DNSCredentials = map[string]string{"access_key_id": "AK", "secret_access_key": "SK"}
	if err := config.ValidateWithDefaults(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := uwastls.NewACMEDNSProvider("route53", cfg.Global.ACME.DNSCredentials, nil); err != nil {
		t.Fatalf("provider from panel-written credentials: %v", err)
	}
}

// config validation names the events a webhook may subscribe to (F13802);
// internal/webhook imports config, so the list lives there. It must be exactly
// the event constants the webhook manager defines.
func TestConfigWebhookEventNamesMatchTheWebhookEvents(t *testing.T) {
	events := []webhook.EventType{
		webhook.EventDomainAdd, webhook.EventDomainDelete, webhook.EventDomainUpdate,
		webhook.EventCertRenewed, webhook.EventCertExpiry,
		webhook.EventBackupCompleted, webhook.EventBackupFailed,
		webhook.EventPHPCrashed, webhook.EventSecurityBlocked, webhook.EventCronFailed,
		webhook.EventLoginSuccess, webhook.EventLoginFailed, webhook.EventTest,
	}
	want := map[string]bool{}
	for _, e := range events {
		want[string(e)] = true
		if err := config.ValidateWebhookEvents([]string{string(e)}); err != nil {
			t.Errorf("event %q is defined by the webhook manager but config rejects it: %v", e, err)
		}
	}
	for _, n := range config.WebhookEventNames() {
		if !want[n] {
			t.Errorf("config accepts event %q that the webhook manager does not define", n)
		}
	}
}
