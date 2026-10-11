package alerting

import (
	"sync"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/logger"
)

// The "once per minute" error_spike dedup must claim its slot atomically:
// concurrent request recorders used to all pass the check before any of them
// recorded the alert, so a spike fired once per racing request (F8200).
func TestErrorSpikeDedupIsAtomicAcrossConcurrentRecorders(t *testing.T) {
	spikes := func(a *Alerter) int {
		n := 0
		for _, h := range a.Alerts() {
			if h.Type == "error_spike" {
				n++
			}
		}
		return n
	}
	for round := 0; round < 100; round++ {
		a := New(true, "", nil, logger.New("error", "text"))
		now := time.Now()
		a.errorWindowMu.Lock()
		for i := 0; i < 20; i++ {
			a.errorWindow = append(a.errorWindow, errorEntry{time: now, isErr: true})
			a.errorWindowErr++
		}
		a.errorWindowMu.Unlock()

		var ready, done sync.WaitGroup
		gate := make(chan struct{})
		for i := 0; i < 16; i++ {
			ready.Add(1)
			done.Add(1)
			go func() {
				defer done.Done()
				ready.Done()
				<-gate
				a.RecordRequest(true)
			}()
		}
		ready.Wait()
		close(gate)
		done.Wait()
		if n := spikes(a); n != 1 {
			t.Fatalf("round %d: %d error_spike alerts from concurrent recorders, want exactly 1", round, n)
		}
	}
}
