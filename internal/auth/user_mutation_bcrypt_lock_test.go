package auth

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// worstValidateLatency runs ValidateSession in a loop while op executes and
// returns the slowest call plus op's duration.
func worstValidateLatency(t *testing.T, m *Manager, token string, op func()) (worst, took time.Duration) {
	t.Helper()
	var mu sync.Mutex
	stop := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			t0 := time.Now()
			m.ValidateSession(token)
			d := time.Since(t0)
			mu.Lock()
			if d > worst {
				worst = d
			}
			mu.Unlock()
			once.Do(func() { close(started) })
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	<-started
	t0 := time.Now()
	op()
	took = time.Since(t0)
	close(stop)
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	return worst, took
}

// CreateUser and UpdateUser hashed the password with the manager-wide write
// lock held, so one admin user create or password reset stalled every
// ValidateSession and API-key check for the whole bcrypt cost (the same defect
// ChangePassword had, F1871). Baseline for "stalled": half the duration of the
// operation, whose time is dominated by bcrypt.
func TestUserMutationsDoNotHoldManagerLockDuringBcrypt(t *testing.T) {
	orig := atomic.LoadInt64(&testBcryptCost)
	atomic.StoreInt64(&testBcryptCost, 12)
	t.Cleanup(func() { atomic.StoreInt64(&testBcryptCost, orig) })
	m, err := NewManager("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	if _, err := m.CreateUser("alice", "", "correct horse battery", RoleUser, nil); err != nil {
		t.Fatal(err)
	}
	sess, err := m.Authenticate("alice", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}

	// Control: with no mutation running, ValidateSession is never slow.
	cw, ct := worstValidateLatency(t, m, sess.Token, func() { time.Sleep(50 * time.Millisecond) })
	if cw >= ct/2 {
		t.Fatalf("control invalid: ValidateSession worst %v over %v idle", cw, ct)
	}

	ops := map[string]func() error{
		"CreateUser": func() error {
			_, err := m.CreateUser("bobby", "", "another long password", RoleUser, nil)
			return err
		},
		"UpdateUser": func() error {
			return m.UpdateUser("alice", &User{Password: "brand new long password"})
		},
	}
	for _, name := range []string{"CreateUser", "UpdateUser"} {
		var opErr error
		worst, took := worstValidateLatency(t, m, sess.Token, func() { opErr = ops[name]() })
		if opErr != nil {
			t.Fatalf("%s: %v", name, opErr)
		}
		t.Logf("EXPECTED: ValidateSession worst < %v ACTUAL: %v (%s took %v)", took/2, worst, name, took)
		if worst >= took/2 {
			t.Errorf("PROBLEM CONFIRMED: %s held the manager lock during bcrypt (ValidateSession stalled %v of %v)", name, worst, took)
		}
	}
}
