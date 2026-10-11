//go:build unix

package phpmanager

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// F15101: php-cgi runs as a master that forks PHP_FCGI_CHILDREN workers.
// Killing only the master (SIGKILL, no process group) orphaned the workers: a
// stopped or removed domain kept executing PHP and kept its listen socket, and
// the monitor's cmd.Wait never returned because the workers held the
// stdout/stderr pipes, so a crash of the master was never noticed.

// masterWithWorker returns a manager whose "php-cgi" is a shell master that
// starts one worker (it inherits the output pipes) and waits for it.
func masterWithWorker(t *testing.T, pidfile string) *Manager {
	t.Helper()
	m := limitsManager(t)
	m.execCommand = func(string, ...string) *exec.Cmd {
		return exec.Command("sh", "-c", "sleep 300 & echo $! > '"+pidfile+"'; wait")
	}
	return m
}

func workerPID(t *testing.T, pidfile string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(pidfile); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 0 {
				t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
				return pid
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("worker never started")
	return 0
}

// goneWithin waits for the (SIGKILLed, so asynchronously reaped) process to
// disappear; a signal-0 probe answers ESRCH once it has.
func goneWithin(pid int, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) != nil {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return syscall.Kill(pid, 0) != nil
}

func TestStoppingADomainKillsItsWorkers(t *testing.T) {
	defer rlimitTestHooks()()
	for name, stop := range map[string]func(*Manager){
		"StopDomain":     func(m *Manager) { _ = m.StopDomain("w.test") },
		"UnassignDomain": func(m *Manager) { m.UnassignDomain("w.test") },
		"StopAll":        func(m *Manager) { m.StopAll() },
	} {
		t.Run(name, func(t *testing.T) {
			pidfile := filepath.Join(t.TempDir(), "worker.pid")
			m := masterWithWorker(t, pidfile)
			if _, err := m.AssignDomain("w.test", "8.4"); err != nil {
				t.Fatal(err)
			}
			if err := m.StartDomain("w.test"); err != nil {
				t.Fatal(err)
			}
			worker := workerPID(t, pidfile)
			if syscall.Kill(worker, 0) != nil {
				t.Fatal("control: the worker is not running before the stop")
			}
			stop(m)
			if !goneWithin(worker, 5*time.Second) {
				t.Errorf("%s left the worker (pid %d) running", name, worker)
			}
		})
	}
}

func TestMasterCrashIsObservedAndWorkersAreCleanedUp(t *testing.T) {
	defer rlimitTestHooks()()
	pidfile := filepath.Join(t.TempDir(), "worker.pid")
	m := masterWithWorker(t, pidfile)
	crashed := make(chan struct{}, 1)
	m.SetOnCrash(func(string) { crashed <- struct{}{} })
	if _, err := m.AssignDomain("c.test", "8.4"); err != nil {
		t.Fatal(err)
	}
	if err := m.StartDomain("c.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.StopAll)
	worker := workerPID(t, pidfile)

	m.domainMu.RLock()
	proc := m.domainMap["c.test"].proc
	m.domainMu.RUnlock()
	_ = proc.cmd.Process.Kill() // the master alone dies (OOM kill, segfault)

	select {
	case <-crashed:
	case <-time.After(10 * time.Second):
		t.Fatal("the master's death was not observed while a worker held the output pipes")
	}
	if !goneWithin(worker, 5*time.Second) {
		t.Errorf("the dead master's worker (pid %d) was left running", worker)
	}
}

// killProcessGroup must still end a command that was NOT started as a group
// leader (kill(-pid) answers ESRCH for it) and must tolerate one that has
// already been reaped.
func TestKillProcessGroupFallsBackToTheMaster(t *testing.T) {
	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sleep: %v", err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	if err := killProcessGroup(cmd); err != nil {
		t.Fatalf("killProcessGroup on a non-leader: %v", err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a command that is not a group leader was left running")
	}
	if err := killProcessGroup(cmd); err != nil {
		t.Errorf("killProcessGroup on a reaped command: %v", err)
	}
	if err := killProcessGroup(nil); err != nil {
		t.Errorf("killProcessGroup(nil): %v", err)
	}
}
