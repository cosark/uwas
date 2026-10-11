package uwastls

import (
	"context"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F7900: StartRenewal returned at once when no ACME email was configured, so
// an operator's own (manual) certificates never got an expiry alert or an OCSP
// refresh. The pass must still run, report the expiring cert, and never try to
// re-issue it.
func TestStartRenewalWithoutACMEAlertsExpiringManualCert(t *testing.T) {
	run := func(t *testing.T, email string, domains []config.Domain) (int, bool) {
		t.Helper()
		m := NewManager(config.ACMEConfig{Email: email, Storage: t.TempDir()}, domains, logger.New("error", "text"))
		m.renewalInitialDelay = 5 * time.Millisecond
		m.renewalInterval = time.Hour
		alerts := make(chan int, 4)
		m.SetOnCertExpiry(func(host string, days int) { alerts <- days })
		renewed := make(chan string, 1)
		m.SetOnCertRenewed(func(host string) { renewed <- host })
		m.certs.Store("manual.test", generateCertWithExpiry(t, "manual.test", 5*24*time.Hour))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m.StartRenewal(ctx)
		select {
		case d := <-alerts:
			select {
			case <-renewed:
				return d, true
			default:
				return d, false
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no expiry alert for a manual certificate")
		}
		return 0, false
	}

	manual := []config.Domain{{Host: "manual.test", SSL: config.SSLConfig{Mode: "manual"}}}
	t.Run("manual domain, no ACME", func(t *testing.T) {
		if d, renewed := run(t, "", manual); d < 0 || d > 5 || renewed {
			t.Errorf("days=%d renewed=%v, want an alert of at most 5 days and no re-issue", d, renewed)
		}
	})
	t.Run("no domains configured, no ACME", func(t *testing.T) {
		if _, renewed := run(t, "", nil); renewed {
			t.Error("a certificate was reported renewed without ACME")
		}
	})
	t.Run("control: ACME configured", func(t *testing.T) {
		if d, _ := run(t, "ops@example.com", manual); d < 0 || d > 5 {
			t.Errorf("days=%d, want at most 5", d)
		}
	})
}
