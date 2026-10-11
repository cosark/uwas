package config

import "testing"

// F13802: the list of events a webhook may subscribe to. The validation that
// uses it ships with the admin API checks (see the F13802 patch).
func TestValidateWebhookEvents(t *testing.T) {
	for _, ok := range [][]string{nil, {}, {"login.failed"}, {"domain.add", "cert.expiry", "test"}} {
		if err := ValidateWebhookEvents(ok); err != nil {
			t.Errorf("events %v rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"login_failed", "Login.Failed", "login.failed ", "loginfailed", "security_blocked", "*", ""} {
		if err := ValidateWebhookEvents([]string{"domain.add", bad}); err == nil {
			t.Errorf("event %q accepted", bad)
		}
	}
	names := WebhookEventNames()
	names[0] = "mutated"
	if WebhookEventNames()[0] == "mutated" {
		t.Error("WebhookEventNames returns the internal slice")
	}
}
