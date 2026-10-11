package autoblock

import (
	"net/netip"
	"testing"
	"time"
)

func trackedAddrs(b *Blocker) int {
	n := 0
	for i := range b.shards {
		b.shards[i].mu.Lock()
		n += len(b.shards[i].tracks)
		b.shards[i].mu.Unlock()
	}
	return n
}

// v6 returns the i-th address of one IPv6 /64.
func v6(i int) netip.Addr {
	var a [16]byte
	copy(a[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1})
	a[8], a[9], a[10], a[11] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
	a[15] = 1
	return netip.AddrFrom16(a)
}

func withCap(t *testing.T, n int) {
	t.Helper()
	old := maxTracksPerShard
	maxTracksPerShard = n
	t.Cleanup(func() { maxTracksPerShard = old })
}

// F15102: the per-address counter table had no ceiling, so a single IPv6 /64
// sending from a million source addresses grew it (and the heap) with the
// attack; records were only dropped once quiet for 2*Window.
func TestTrackTableIsBoundedUnderAddressFlood(t *testing.T) {
	withCap(t, 4)
	b := New(Config{Enabled: true, BlockDuration: time.Hour}, testLogger())
	now := time.Now()

	// Control: a source seen before the flood is tracked and keeps counting.
	known := v6(0)
	b.withTrack(known, now, func(tr *track) { tr.conns++ })

	for i := 1; i <= 20000; i++ {
		b.withTrack(v6(i), now, func(tr *track) { tr.conns++ })
	}
	if got, ceiling := trackedAddrs(b), shardCount*4; got > ceiling {
		t.Errorf("%d tracked addresses after the flood, ceiling %d", got, ceiling)
	}

	snap := b.withTrack(known, now, func(tr *track) { tr.conns++ })
	if snap.conns != 2 {
		t.Errorf("a tracked source stopped being counted under flood: conns=%d, want 2", snap.conns)
	}
}

// A full table first reclaims addresses that went quiet, so legitimate new
// sources are tracked again once the flood is over.
func TestFullTrackTableReclaimsQuietAddresses(t *testing.T) {
	withCap(t, 2)
	b := New(Config{Enabled: true, BlockDuration: time.Hour}, testLogger())
	start := time.Now()
	for i := 0; i < 5000; i++ {
		b.withTrack(v6(i), start, func(tr *track) { tr.conns++ })
	}
	if trackedAddrs(b) == 0 {
		t.Fatal("nothing tracked")
	}

	// Long after the flood (past 2*Window and the once-a-second sweep guard) a
	// new source must be remembered.
	later := start.Add(time.Hour)
	fresh := v6(1 << 20)
	b.withTrack(fresh, later, func(tr *track) { tr.conns++ })
	sh := b.shardFor(fresh)
	sh.mu.Lock()
	_, ok := sh.tracks[fresh]
	sh.mu.Unlock()
	if !ok {
		t.Error("a new source was not tracked although every old record had gone quiet")
	}
}

// Below the ceiling every address is tracked, as before.
func TestTrackTableBelowCeilingTracksEverything(t *testing.T) {
	b := New(Config{Enabled: true, BlockDuration: time.Hour}, testLogger())
	now := time.Now()
	for i := 0; i < 3000; i++ {
		b.withTrack(v6(i), now, func(tr *track) { tr.conns++ })
	}
	if got := trackedAddrs(b); got != 3000 {
		t.Errorf("%d tracked, want 3000", got)
	}
}
