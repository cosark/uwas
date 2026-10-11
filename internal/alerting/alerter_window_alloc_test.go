package alerting

import (
	"runtime"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/logger"
)

// RecordRequest runs on every request. Pruning one expired entry used to copy
// the whole window into a fresh slice, so each request allocated O(window)
// bytes (F4300).
func TestRecordRequestPruneDoesNotCopyWindow(t *testing.T) {
	a := New(true, "", nil, logger.New("error", "text"))
	now := time.Now()
	const size, calls = 60000, 300
	a.errorWindow = make([]errorEntry, size)
	for i := range a.errorWindow {
		a.errorWindow[i] = errorEntry{time: now}
	}
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	for i := 0; i < calls; i++ {
		a.errorWindowMu.Lock()
		a.errorWindow[0].time = now.Add(-time.Hour) // one entry ages out
		a.errorWindowMu.Unlock()
		a.RecordRequest(false)
	}
	runtime.ReadMemStats(&m1)
	if per := (m1.TotalAlloc - m0.TotalAlloc) / calls; per > 64*1024 {
		t.Fatalf("RecordRequest allocated %d B/call with one expiring entry, want < 64KiB", per)
	}
	a.errorWindowMu.Lock()
	defer a.errorWindowMu.Unlock()
	if got := len(a.errorWindow); got != size {
		t.Fatalf("window len = %d, want %d (one pruned, one appended per call)", got, size)
	}
}

// The size cap must keep the newest entries and the running error count in
// step with the entries actually retained.
func TestRecordRequestWindowCapKeepsErrCount(t *testing.T) {
	a := New(true, "", nil, logger.New("error", "text"))
	now := time.Now()
	const max = 100000
	a.errorWindow = make([]errorEntry, max)
	for i := range a.errorWindow {
		isErr := i < 10 // the ten oldest entries are errors
		a.errorWindow[i] = errorEntry{time: now, isErr: isErr}
		if isErr {
			a.errorWindowErr++
		}
	}
	a.RecordRequest(false) // overflows by one: the oldest (an error) is dropped
	a.errorWindowMu.Lock()
	defer a.errorWindowMu.Unlock()
	if len(a.errorWindow) != max {
		t.Fatalf("len = %d, want %d", len(a.errorWindow), max)
	}
	n := 0
	for _, e := range a.errorWindow {
		if e.isErr {
			n++
		}
	}
	if n != a.errorWindowErr || n != 9 {
		t.Fatalf("errors in window = %d, counter = %d, want 9", n, a.errorWindowErr)
	}
}
