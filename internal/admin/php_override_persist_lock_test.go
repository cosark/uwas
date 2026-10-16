package admin

import (
	"strings"
	"testing"
	"time"
)

// persistDomainPHPOverrides rewrites a domain file by read-modify-write. It
// must serialize with persistConfig (persistMu), otherwise a persistConfig that
// lands between its read and its write is overwritten with the stale copy.
// The gate: persistMu is held, as an in-flight persistConfig holds it; the
// override persist must not touch the domain file until the lock is released.
func TestPersistDomainPHPOverridesWaitsForPersistMu(t *testing.T) {
	srv, dir := newPHPOverrideServer(t)
	if err := srv.phpMgr.SetDomainConfig("example.com", "memory_limit", "512M"); err != nil {
		t.Fatal(err)
	}

	srv.persistMu.Lock()
	done := make(chan struct{})
	go func() {
		srv.persistDomainPHPOverrides("example.com")
		close(done)
	}()
	select {
	case <-done:
		srv.persistMu.Unlock()
		t.Fatalf("EXPECTED: persistDomainPHPOverrides blocks while persistMu is held\nACTUAL: it completed and wrote the domain file without the lock")
	case <-time.After(2 * time.Second):
	}
	if strings.Contains(readDomainFile(t, dir, "example.com"), "512M") {
		srv.persistMu.Unlock()
		t.Fatal("domain file written while persistMu was held")
	}
	srv.persistMu.Unlock()
	<-done
	if !strings.Contains(readDomainFile(t, dir, "example.com"), "512M") {
		t.Fatal("override missing after the lock was released")
	}
}

// Control/edge: with no persist in flight the call completes promptly, and a
// repeated call is idempotent.
func TestPersistDomainPHPOverridesCompletesWhenUnlocked(t *testing.T) {
	srv, dir := newPHPOverrideServer(t)
	if err := srv.phpMgr.SetDomainConfig("example.com", "memory_limit", "512M"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		srv.persistDomainPHPOverrides("example.com")
	}
	if got := readDomainFile(t, dir, "example.com"); strings.Count(got, "memory_limit") != 1 || !strings.Contains(got, "512M") {
		t.Fatalf("unexpected domain file:\n%s", got)
	}
	// persistMu is released again: a following persistConfig must not deadlock.
	if err := srv.persistConfig(); err != nil {
		t.Fatal(err)
	}
}
