package config

import (
	"strings"
	"testing"
)

// F13802: internal/webhook compares an event to a subscription with ==, so a
// subscription naming an event any other way never fires. Validation must say so.
func TestValidateRejectsWebhookEventsThatNeverFire(t *testing.T) {
	cfgWith := func(events ...string) *Config {
		cfg := &Config{}
		cfg.Global.Webhooks = []WebhookConfig{{URL: "https://hooks.example.com/x", Events: events, Enabled: true}}
		return cfg
	}
	for _, ok := range [][]string{nil, {}, {"login.failed"}, {"domain.add", "cert.expiry", "test"}} {
		if err := ValidateWithDefaults(cfgWith(ok...)); err != nil {
			t.Errorf("events %v rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"login_failed", "Login.Failed", "login.failed ", "loginfailed", "security_blocked", "*"} {
		err := ValidateWithDefaults(cfgWith("domain.add", bad))
		if err == nil || !strings.Contains(err.Error(), "global.webhooks[0].events") {
			t.Errorf("event %q: err = %v, want a global.webhooks[0].events error", bad, err)
		}
	}
	if err := ValidateWebhookEvents([]string{"nope"}); err == nil {
		t.Error("ValidateWebhookEvents accepted an unknown name")
	}
}
