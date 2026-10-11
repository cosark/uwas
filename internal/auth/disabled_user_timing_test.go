package auth

import (
	"fmt"
	"sort"
	"sync/atomic"
	"testing"
	"time"
)

// F10400: a disabled account used to be rejected before any bcrypt work, so it
// answered orders of magnitude faster than a wrong password on an enabled
// account and its existence leaked through response timing (VULN-025 had only
// equalized the missing-user path).
func TestDisabledUserSpendsBcryptTime(t *testing.T) {
	orig := atomic.LoadInt64(&testBcryptCost)
	atomic.StoreInt64(&testBcryptCost, 8)
	t.Cleanup(func() { atomic.StoreInt64(&testBcryptCost, orig) })

	m := newTestManager(t)
	const pw = "correct-horse-battery-staple-1"
	for _, u := range []string{"enabled-user", "disabled-user"} {
		if _, err := m.CreateUser(u, u+"@example.com", pw, RoleUser, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.UpdateUser("disabled-user", &User{Enabled: false, EnabledSet: true}); err != nil {
		t.Fatal(err)
	}

	median := func(user string) time.Duration {
		var ds []time.Duration
		for i := 0; i < 3; i++ {
			ip := fmt.Sprintf("198.51.100.%d", i+1) // distinct lockout keys
			start := time.Now()
			if _, err := m.AuthenticateFrom(user, "wrong-password-value", ip); err == nil {
				t.Fatalf("%s: wrong password authenticated", user)
			}
			ds = append(ds, time.Since(start))
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		return ds[1]
	}

	enabledWrong := median("enabled-user")
	disabled := median("disabled-user")
	if disabled < enabledWrong/4 {
		t.Errorf("disabled account answered in %v, a wrong password on an enabled one takes %v: the timing reveals the account exists", disabled, enabledWrong)
	}

	// A correct password must still not log a disabled user in.
	if _, err := m.AuthenticateFrom("disabled-user", pw, "198.51.100.9"); err == nil {
		t.Error("disabled user authenticated with the correct password")
	}
}
