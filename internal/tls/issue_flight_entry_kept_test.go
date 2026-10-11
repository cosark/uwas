package uwastls

import (
	"context"
	"crypto/tls"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F15100: the per-host flight entry belongs to the ORDER, not to the caller
// that led it. A handshake that drops while the (detached) order is still in
// flight used to remove the entry, so the next handshake for the same host
// started a second concurrent order; a few of those exhaust the CA's
// duplicate-certificate limit for the host.
func TestIssueFlightEntryOutlivesCancelledLeader(t *testing.T) {
	host := "entry-kept.example"
	m := NewManager(config.ACMEConfig{Storage: t.TempDir()}, nil, logger.New("error", "text"))
	fresh, certPEM, keyPEM := generateTestCert(t, host)

	var orders atomic.Int64
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	m.acmeObtainFunc = func(ctx context.Context, names []string) (*tls.Certificate, []byte, []byte, error) {
		orders.Add(1)
		started <- struct{}{}
		select {
		case <-ctx.Done():
			return nil, nil, nil, ctx.Err()
		case <-release:
			return fresh, certPEM, keyPEM, nil
		}
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() { _, err := m.obtainCert(leaderCtx, host, false); leaderDone <- err }()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("order never started")
	}

	// The leader goes away while the order is gated in flight.
	cancelLeader()
	select {
	case err := <-leaderDone:
		if err == nil {
			t.Fatal("cancelled leader returned nil")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled leader still blocked")
	}
	if _, ok := m.obtainFlight.Load(host); !ok {
		t.Fatal("flight entry was dropped while its order is still in flight")
	}

	// A new caller joins that order instead of starting a second one.
	joinerDone := make(chan error, 1)
	go func() { _, err := m.obtainCert(context.Background(), host, false); joinerDone <- err }()
	deadline := time.Now().Add(10 * time.Second)
	for parkedInFlightCount("(*Manager).issueCert") < 1 {
		if time.Now().After(deadline) {
			t.Fatal("joiner never reached the flight")
		}
		time.Sleep(time.Millisecond)
	}

	close(release)
	select {
	case err := <-joinerDone:
		if err != nil {
			t.Fatalf("joiner: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("joiner never finished")
	}
	if got := orders.Load(); got != 1 {
		t.Errorf("%d ACME orders for one host, want 1", got)
	}
	// The entry is removed when the order ends, so the map does not grow with
	// attacker-chosen SNI names.
	if _, ok := m.obtainFlight.Load(host); ok {
		t.Error("flight entry still present after the order ended")
	}
}
