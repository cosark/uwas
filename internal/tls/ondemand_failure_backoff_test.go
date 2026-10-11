package uwastls

import (
	"context"
	"crypto/tls"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

func onDemandManager(t *testing.T, obtain func(host string) error) (*Manager, *atomic.Int64) {
	t.Helper()
	domains := []config.Domain{
		{Host: "od.test", SSL: config.SSLConfig{Mode: "auto"}},
		{Host: "other.test", SSL: config.SSLConfig{Mode: "auto"}},
	}
	m := NewManager(config.ACMEConfig{Email: "ops@example.com", OnDemand: true, Storage: t.TempDir()}, domains, logger.New("error", "text"))
	var calls atomic.Int64
	m.acmeObtainFunc = func(ctx context.Context, names []string) (*tls.Certificate, []byte, []byte, error) {
		calls.Add(1)
		if err := obtain(names[0]); err != nil {
			return nil, nil, nil, err
		}
		c, certPEM, keyPEM := generateTestCertWithExpiry(t, names[0], 90*24*time.Hour)
		return c, certPEM, keyPEM, nil
	}
	return m, &calls
}

func hello(m *Manager, host string) error {
	_, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
	return err
}

// F7901: every handshake for a host whose on-demand order had failed started
// another CA order, so a misconfigured host hit the CA's failed-validation
// limit and spent the shared on-demand budget.
func TestOnDemandFailedOrderIsNotRetriedImmediately(t *testing.T) {
	boom := errors.New("acme: validation failed")
	m, calls := onDemandManager(t, func(host string) error {
		if host == "od.test" {
			return boom
		}
		return nil
	})

	for i := 0; i < 5; i++ {
		if err := hello(m, "od.test"); err == nil {
			t.Fatal("handshake for a failing host succeeded")
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("5 handshakes caused %d CA orders, want 1", got)
	}

	// Another host is unaffected, and a success is cached.
	if err := hello(m, "other.test"); err != nil {
		t.Fatalf("other host: %v", err)
	}
	if err := hello(m, "other.test"); err != nil {
		t.Fatalf("other host again: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("orders after other.test = %d, want 2", got)
	}
}

func TestOnDemandBackoffEndsAndClearsOnSuccess(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	m, calls := onDemandManager(t, func(string) error {
		if fail.Load() {
			return errors.New("acme: validation failed")
		}
		return nil
	})
	m.onDemandBackoffBase = 20 * time.Millisecond

	if err := hello(m, "od.test"); err == nil {
		t.Fatal("first handshake should fail")
	}
	// The backoff is not over: no order.
	hello(m, "od.test")
	if got := calls.Load(); got != 1 {
		t.Fatalf("orders during backoff = %d, want 1", got)
	}

	// Once it elapses the host is tried again, and a success clears the record.
	fail.Store(false)
	deadline := time.Now().Add(5 * time.Second)
	for hello(m, "od.test") != nil {
		if time.Now().After(deadline) {
			t.Fatal("host never retried after the backoff elapsed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if m.onDemandBackedOff("od.test") {
		t.Error("backoff survived a successful order")
	}
	if got := m.onDemandFailCount.Load(); got != 0 {
		t.Errorf("tracked failures = %d after success, want 0", got)
	}
}

func TestOnDemandCancelledHandshakeIsNotAFailure(t *testing.T) {
	m, _ := onDemandManager(t, func(string) error { return context.Canceled })
	hello(m, "od.test")
	if m.onDemandBackedOff("od.test") {
		t.Error("a cancelled order put the host into backoff")
	}
}
