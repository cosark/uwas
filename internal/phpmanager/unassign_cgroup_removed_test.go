package phpmanager

import (
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/rlimit"
)

// F11800: UnassignDomain killed the worker but never removed the domain's
// cgroup, so every deleted domain left an empty cgroup directory behind.
func TestUnassignDomainRemovesCgroupOnceWorkerExits(t *testing.T) {
	defer rlimitTestHooks()()
	removed := make(chan string, 4)
	rlimitApply = func(domain string, l rlimit.Limits) (string, error) {
		return "/sys/fs/cgroup/uwas/" + domain, nil
	}
	rlimitAssignPID = func(string, int) error { return nil }
	rlimitRemove = func(domain string) error { removed <- domain; return nil }

	m := limitsManager(t)
	if _, err := m.AssignDomain("gone.test", "8.4"); err != nil {
		t.Fatalf("AssignDomain: %v", err)
	}
	m.SetDomainLimits("gone.test", rlimit.Limits{MemoryMB: 128})
	if err := m.StartDomain("gone.test"); err != nil {
		t.Fatalf("StartDomain: %v", err)
	}

	m.UnassignDomain("gone.test")

	select {
	case got := <-removed:
		if got != "gone.test" {
			t.Errorf("removed cgroup of %q, want gone.test", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cgroup of an unassigned domain was never removed")
	}
}

// A domain that crashes while still assigned keeps its cgroup: the restart
// reuses the directory.
func TestCrashedAssignedDomainKeepsCgroup(t *testing.T) {
	defer rlimitTestHooks()()
	rlimitApply = func(domain string, l rlimit.Limits) (string, error) {
		return "/sys/fs/cgroup/uwas/" + domain, nil
	}
	rlimitAssignPID = func(string, int) error { return nil }
	rlimitRemove = func(domain string) error {
		t.Errorf("cgroup of still-assigned %q removed", domain)
		return nil
	}

	m := limitsManager(t)
	crashed := make(chan struct{}, 1)
	m.SetOnCrash(func(string) { crashed <- struct{}{} })
	if _, err := m.AssignDomain("live.test", "8.4"); err != nil {
		t.Fatalf("AssignDomain: %v", err)
	}
	m.SetDomainLimits("live.test", rlimit.Limits{MemoryMB: 128})
	if err := m.StartDomain("live.test"); err != nil {
		t.Fatalf("StartDomain: %v", err)
	}
	t.Cleanup(func() { _ = m.StopDomain("live.test") })

	m.domainMu.RLock()
	proc := m.domainMap["live.test"].proc
	m.domainMu.RUnlock()
	_ = proc.cmd.Process.Kill() // crash, not an operator stop

	select {
	case <-crashed:
	case <-time.After(5 * time.Second):
		t.Fatal("crash was not observed")
	}
}
