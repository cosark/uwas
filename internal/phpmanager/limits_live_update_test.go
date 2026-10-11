package phpmanager

import (
	"errors"
	"testing"

	"github.com/uwaserver/uwas/internal/rlimit"
)

// F16301: a limit changed while a domain's worker runs was recorded and left
// at that; the cgroup kept the old caps until the next start.
func TestUpdateDomainLimitsReachesTheRunningWorker(t *testing.T) {
	loose := rlimit.Limits{MemoryMB: 1024, PIDMax: 100}
	tight := rlimit.Limits{MemoryMB: 64, PIDMax: 100}

	start := func(t *testing.T, initial rlimit.Limits) (*Manager, *[]rlimit.Limits) {
		t.Helper()
		restore := rlimitTestHooks()
		t.Cleanup(restore)
		var applied []rlimit.Limits
		rlimitApply = func(domain string, l rlimit.Limits) (string, error) {
			applied = append(applied, l)
			if l == (rlimit.Limits{}) {
				return "", nil
			}
			return "/sys/fs/cgroup/uwas/" + domain, nil
		}
		rlimitAssignPID = func(string, int) error { return nil }
		rlimitRemove = func(string) error { return nil }
		m := limitsManager(t)
		if _, err := m.AssignDomain("live.test", "8.4"); err != nil {
			t.Fatal(err)
		}
		m.SetDomainLimits("live.test", initial)
		if err := m.StartDomain("live.test"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = m.StopDomain("live.test") })
		return m, &applied
	}

	t.Run("a tightened limit is written to the live cgroup", func(t *testing.T) {
		m, applied := start(t, loose)
		before := len(*applied)
		changed, restart := m.UpdateDomainLimits("live.test", tight)
		if !changed || restart {
			t.Fatalf("changed=%v restartNeeded=%v, want true,false", changed, restart)
		}
		if len(*applied) != before+1 || (*applied)[before] != tight {
			t.Errorf("Apply calls after the change: %v, want one with %+v", (*applied)[before:], tight)
		}
		if got, _ := m.DomainLimits("live.test"); got != tight {
			t.Errorf("recorded limits %+v, want %+v", got, tight)
		}
	})

	t.Run("lifting every limit is applied too", func(t *testing.T) {
		m, applied := start(t, loose)
		before := len(*applied)
		if changed, restart := m.UpdateDomainLimits("live.test", rlimit.Limits{}); !changed || restart {
			t.Fatalf("changed=%v restartNeeded=%v, want true,false", changed, restart)
		}
		if len(*applied) != before+1 || (*applied)[before] != (rlimit.Limits{}) {
			t.Errorf("zero limits were not passed to Apply: %v", (*applied)[before:])
		}
	})

	t.Run("a worker outside any cgroup needs a restart to be limited", func(t *testing.T) {
		m, applied := start(t, rlimit.Limits{})
		before := len(*applied)
		changed, restart := m.UpdateDomainLimits("live.test", tight)
		if !changed || !restart {
			t.Fatalf("changed=%v restartNeeded=%v, want true,true", changed, restart)
		}
		if len(*applied) != before {
			t.Errorf("Apply ran for a worker that is in no cgroup: %v", (*applied)[before:])
		}
		// Control: lifting a limit nobody applied needs no restart.
		if _, restart := m.UpdateDomainLimits("live.test", rlimit.Limits{}); restart {
			t.Error("lifting limits on an unlimited worker asked for a restart")
		}
	})

	t.Run("an unchanged limit does nothing", func(t *testing.T) {
		m, applied := start(t, loose)
		before := len(*applied)
		if changed, restart := m.UpdateDomainLimits("live.test", loose); changed || restart {
			t.Errorf("changed=%v restartNeeded=%v for identical limits", changed, restart)
		}
		if len(*applied) != before {
			t.Error("Apply ran for identical limits")
		}
	})

	t.Run("a stopped domain records them for the next start", func(t *testing.T) {
		m, applied := start(t, loose)
		if err := m.StopDomain("live.test"); err != nil {
			t.Fatal(err)
		}
		before := len(*applied)
		changed, restart := m.UpdateDomainLimits("live.test", tight)
		if !changed || restart || len(*applied) != before {
			t.Errorf("changed=%v restartNeeded=%v applies=%d, want true,false,0", changed, restart, len(*applied)-before)
		}
		if got, _ := m.DomainLimits("live.test"); got != tight {
			t.Errorf("recorded limits %+v, want %+v", got, tight)
		}
	})

	t.Run("an unassigned domain is ignored", func(t *testing.T) {
		m, _ := start(t, loose)
		if changed, restart := m.UpdateDomainLimits("nobody.test", tight); changed || restart {
			t.Error("limits were accepted for a domain with no PHP assignment")
		}
	})

	t.Run("a cgroup that cannot be rewritten asks for a restart", func(t *testing.T) {
		m, _ := start(t, loose)
		rlimitApply = func(string, rlimit.Limits) (string, error) { return "", errors.New("read-only cgroup") }
		changed, restart := m.UpdateDomainLimits("live.test", tight)
		if !changed || !restart {
			t.Errorf("changed=%v restartNeeded=%v, want true,true", changed, restart)
		}
	})
}
