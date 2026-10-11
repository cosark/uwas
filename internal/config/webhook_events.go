package config

import (
	"fmt"
	"strings"
)

// webhookEventNames are the event names an outbound webhook may subscribe to.
// internal/webhook compares an event to a subscription with ==, so a
// subscription that names an event any other way ("login_failed",
// "Login.Failed") never fires (F13802). internal/webhook imports this package,
// so the list lives here; a test in internal/server keeps it in step with the
// event constants.
var webhookEventNames = []string{
	"domain.add", "domain.delete", "domain.update",
	"cert.renewed", "cert.expiry",
	"backup.completed", "backup.failed",
	"php.crashed", "security.blocked", "cron.failed",
	"login.success", "login.failed",
	"test",
}

// WebhookEventNames returns the event names a webhook subscription may use.
func WebhookEventNames() []string {
	return append([]string(nil), webhookEventNames...)
}

// ValidateWebhookEvents reports the first event name in a webhook's events list
// that no event is ever fired under. An empty list means every event.
func ValidateWebhookEvents(events []string) error {
	for _, e := range events {
		known := false
		for _, n := range webhookEventNames {
			if e == n {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("unknown webhook event %q (must be one of %s)", e, strings.Join(webhookEventNames, ", "))
		}
	}
	return nil
}
