package uwastls

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F7600: the per-host flight runs the ACME order under the context of
// whichever caller arrived first. When that caller goes away (a visitor that
// drops its handshake, an admin request that ends) the order was aborted for
// every other caller sharing the flight. The order now runs detached and each
// caller waits under its own context.
func TestIssueFlightSurvivesLeaderCancellation(t *testing.T) {
	m := NewManager(config.ACMEConfig{Storage: t.TempDir()}, nil, logger.New("error", "text"))
	fresh, certPEM, keyPEM := generateTestCert(t, "leader-cancel.example")

	started := make(chan struct{}, 4)
	release := make(chan struct{})
	m.acmeObtainFunc = func(ctx context.Context, names []string) (*tls.Certificate, []byte, []byte, error) {
		started <- struct{}{}
		select {
		case <-ctx.Done():
			return nil, nil, nil, ctx.Err()
		case <-release:
			return fresh, certPEM, keyPEM, nil
		}
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()
	leaderDone := make(chan error, 1)
	go func() {
		_, err := m.obtainCert(leaderCtx, "leader-cancel.example", false)
		leaderDone <- err
	}()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("leader never reached ACME")
	}

	type result struct {
		cert *tls.Certificate
		err  error
	}
	waiterDone := make(chan result, 1)
	go func() {
		c, err := m.obtainCert(context.Background(), "leader-cancel.example", false)
		waiterDone <- result{c, err}
	}()
	deadline := time.Now().Add(10 * time.Second)
	// Leader and waiter both wait in doIssue.
	for parkedInFlightCount("(*Manager).issueCert") < 2 {
		if time.Now().After(deadline) {
			t.Fatal("waiter never joined the flight")
		}
		time.Sleep(time.Millisecond)
	}

	// The leader's context ends while the order is still in flight (gated:
	// the order is released only after the leader has returned).
	cancelLeader()
	select {
	case err := <-leaderDone:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("cancelled leader returned %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled leader still blocked on the shared flight")
	}

	close(release)
	select {
	case r := <-waiterDone:
		if r.err != nil || r.cert == nil {
			t.Fatalf("waiter with a live context got cert=%v err=%v, want the certificate", r.cert != nil, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("waiter never completed")
	}
	if _, ok := m.certs.Load("leader-cancel.example"); !ok {
		t.Error("issued certificate was not stored")
	}
}

// A caller whose own context ends stops waiting, but the order carries on for
// the callers that remain.
func TestIssueCertCallerStopsWaitingOnOwnContext(t *testing.T) {
	m := NewManager(config.ACMEConfig{Storage: t.TempDir()}, nil, logger.New("error", "text"))
	fresh, certPEM, keyPEM := generateTestCert(t, "own-ctx.example")
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	m.acmeObtainFunc = func(ctx context.Context, names []string) (*tls.Certificate, []byte, []byte, error) {
		started <- struct{}{}
		<-release
		return fresh, certPEM, keyPEM, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := m.obtainCert(ctx, "own-ctx.example", false)
		done <- err
	}()
	<-started
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("err = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("caller kept waiting past its own deadline")
	}

	// The order carries on without that caller and still stores its result
	// (waiting for it also keeps the flight from outliving the test's TempDir).
	close(release)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, ok := m.certs.Load("own-ctx.example"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the order did not complete after its caller left")
		}
		time.Sleep(time.Millisecond)
	}
	// Save runs right after the store; let it finish before TempDir cleanup.
	for i := 0; i < 1000; i++ {
		if _, err := m.storage.LoadMeta("own-ctx.example"); err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
}

// DoChan runs the order on its own goroutine, so a panic in it has to come
// back as an error instead of ending the process.
func TestIssueFlightPanicBecomesError(t *testing.T) {
	m := NewManager(config.ACMEConfig{Storage: t.TempDir()}, nil, logger.New("error", "text"))
	m.acmeObtainFunc = func(ctx context.Context, names []string) (*tls.Certificate, []byte, []byte, error) {
		panic("boom")
	}
	_, err := m.obtainCert(context.Background(), "panic.example", false)
	if err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("err = %v, want a panic error", err)
	}
}
