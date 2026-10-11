package uwastls

import (
	"context"
	"crypto/tls"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// parkedInSingleflight reports whether a goroutine running fn is blocked
// waiting on an in-flight singleflight call.
func parkedInSingleflight(fn string) bool {
	return parkedInFlightCount(fn) > 0
}

// parkedInFlightCount counts the goroutines running fn that wait on an
// in-flight issuance. A caller waits in doIssue's select, on the flight's
// result channel and its own context (F7600).
func parkedInFlightCount(fn string) int {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	count := 0
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(g, fn) && strings.Contains(g, "(*Manager).doIssue") && strings.Contains(g, "[select") {
			count++
		}
	}
	return count
}

// A scheduled renewal and a concurrent Force Renew of the same host must
// share one ACME issuance instead of ordering two certificates.
func TestScheduledRenewalCoalescesWithForceRenew(t *testing.T) {
	for _, tc := range []struct {
		name          string
		leader, joins func(m *Manager)
		joinerFn      string
	}{
		{
			name:     "renewal leads",
			leader:   func(m *Manager) { m.checkRenewals(context.Background()) },
			joins:    func(m *Manager) { _ = m.RenewCert(context.Background(), "renew.example") },
			joinerFn: "(*Manager).RenewCert",
		},
		{
			name:     "force renew leads",
			leader:   func(m *Manager) { _ = m.RenewCert(context.Background(), "renew.example") },
			joins:    func(m *Manager) { m.checkRenewals(context.Background()) },
			joinerFn: "(*Manager).renewOne",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(config.ACMEConfig{Storage: t.TempDir()}, nil, logger.New("error", "text"))
			m.certs.Store("renew.example", generateCertWithExpiry(t, "renew.example", 5*24*time.Hour))
			fresh, certPEM, keyPEM := generateTestCert(t, "renew.example")
			var renewed atomic.Int32
			m.SetOnCertRenewed(func(string) { renewed.Add(1) })

			var calls atomic.Int32
			started := make(chan struct{}, 4)
			release := make(chan struct{})
			m.acmeObtainFunc = func(ctx context.Context, names []string) (*tls.Certificate, []byte, []byte, error) {
				calls.Add(1)
				started <- struct{}{}
				<-release
				return fresh, certPEM, keyPEM, nil
			}

			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); tc.leader(m) }()
			deadline := time.After(10 * time.Second)
			select {
			case <-started:
			case <-deadline:
				t.Fatal("leader never reached ACME")
			}
			go func() { defer wg.Done(); tc.joins(m) }()
		wait:
			for {
				select {
				case <-started:
					break wait // second issuance: the bug
				case <-deadline:
					close(release)
					t.Fatal("second caller neither joined nor issued")
				default:
				}
				if parkedInSingleflight(tc.joinerFn) {
					break wait
				}
				runtime.Gosched()
			}
			close(release)
			wg.Wait()

			if got := calls.Load(); got != 1 {
				t.Errorf("ACME issuances = %d, want 1", got)
			}
			if got, _ := m.certs.Load("renew.example"); got != any(fresh) {
				t.Error("renewed certificate not stored")
			}
			if got := renewed.Load(); got != 1 {
				t.Errorf("onCertRenewed calls = %d, want 1", got)
			}
		})
	}
}
