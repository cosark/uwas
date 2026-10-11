package autoblock

import (
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"
)

func sbAddr(i int) netip.Addr {
	return netip.MustParseAddr(fmt.Sprintf("2001:db8:%x:%x::1", i>>16, i&0xffff))
}

// F15203: installing a block must not cost more as the list grows. The enforced
// view used to be rebuilt in full for every block, so the Nth one allocated
// O(N) and ran under b.mu; measuring bytes allocated rather than elapsed time
// keeps the check independent of the machine.
func TestBlockInstallCostDoesNotGrowWithList(t *testing.T) {
	b := testBlocker(t, nil)
	const base, extra = 4000, 2000
	for i := 0; i < base; i++ {
		b.apply(sbAddr(i), ReasonManual, 1, 1, time.Hour)
	}
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	for i := base; i < base+extra; i++ {
		b.apply(sbAddr(i), ReasonManual, 1, 1, time.Hour)
	}
	runtime.ReadMemStats(&m1)
	if got := (m1.TotalAlloc - m0.TotalAlloc) >> 20; got > 32 {
		t.Errorf("installing %d blocks onto a list of %d allocated %d MiB, want at most 32", extra, base, got)
	}
	if !b.Blocked(sbAddr(0)) || !b.Blocked(sbAddr(base+extra-1)) {
		t.Error("installed blocks are not enforced")
	}
}

// F15203: the escalation history is bounded, and trimming keeps the addresses
// that are blocked right now.
func TestHistoryIsBounded(t *testing.T) {
	old := maxHistory
	maxHistory = 100
	defer func() { maxHistory = old }()

	b := testBlocker(t, nil)
	b.apply(sbAddr(1), ReasonManual, 1, 3, time.Hour) // active: must survive trimming
	b.mu.Lock()
	for i := 0; i < 500; i++ {
		b.history[netip.AddrFrom4([4]byte{12, 0, byte(i >> 8), byte(i)})] = 1
	}
	b.mu.Unlock()

	b.apply(sbAddr(2), ReasonManual, 1, 1, time.Hour)

	b.mu.Lock()
	n, lvl := len(b.history), b.history[sbAddr(1)]
	b.mu.Unlock()
	if n > maxHistory {
		t.Errorf("history has %d entries, limit is %d", n, maxHistory)
	}
	if lvl != 3 {
		t.Errorf("trimming dropped the history of a block that is still active (level %d, want 3)", lvl)
	}
}

// The sharded view must agree with the block list through every kind of change.
func TestEnforcedViewTracksBlockList(t *testing.T) {
	b := testBlocker(t, nil)
	enforced := func() int {
		n := 0
		for i := range b.vshards {
			b.vshards[i].mu.RLock()
			n += len(b.vshards[i].set)
			b.vshards[i].mu.RUnlock()
		}
		return n
	}
	check := func(step string, want int) {
		t.Helper()
		if got := enforced(); got != want {
			t.Errorf("%s: %d addresses enforced, want %d", step, got, want)
		}
		if got := int(b.blockedN.Load()); got != want {
			t.Errorf("%s: blockedN = %d, want %d", step, got, want)
		}
	}

	for i := 0; i < 50; i++ {
		b.apply(sbAddr(i), ReasonManual, 1, 1, time.Hour)
	}
	check("after 50 blocks", 50)
	b.apply(sbAddr(0), ReasonManual, 1, 2, time.Hour) // same address again
	check("after re-blocking one address", 50)

	if err := b.Unblock(sbAddr(1).String()); err != nil {
		t.Fatal(err)
	}
	check("after Unblock", 49)
	if b.Blocked(sbAddr(1)) || !b.Blocked(sbAddr(2)) {
		t.Error("Unblock lifted the wrong address")
	}

	b.mu.Lock()
	b.blocked[sbAddr(2)].ExpiresAt = time.Now().Add(-time.Second)
	b.mu.Unlock()
	b.expire()
	check("after expiry", 48)
	if b.Blocked(sbAddr(2)) {
		t.Error("an expired block is still enforced")
	}

	b.SetWhitelist([]string{"2001:db8:0:3::/64"})
	check("after whitelisting one source", 47)
	if b.Blocked(sbAddr(3)) {
		t.Error("a whitelisted source is still blocked")
	}
}

// Readers run lock-free of b.mu while blocks come and go; -race checks the
// sharded view's locking.
func TestBlockedIsSafeAgainstConcurrentChanges(t *testing.T) {
	b := testBlocker(t, nil)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func(r int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
					b.Blocked(sbAddr((i*7 + r) % 400))
				}
			}
		}(r)
	}
	for i := 0; i < 400; i++ {
		b.apply(sbAddr(i), ReasonManual, 1, 1, time.Hour)
	}
	for i := 0; i < 400; i += 2 {
		_ = b.Unblock(sbAddr(i).String())
	}
	b.expire()
	close(stop)
	wg.Wait()
	if got := int(b.blockedN.Load()); got != 200 {
		t.Errorf("blockedN = %d after 400 blocks and 200 unblocks, want 200", got)
	}
}
