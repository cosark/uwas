package services

import (
	"errors"
	"os/exec"
	"testing"
	"time"
)

// F5901: a wedged systemctl must not pin the dashboard-polled listing; the
// query is killed after statusTimeout and the listing stops there instead of
// repeating the wait for every remaining service.
func TestListServicesBoundedWhenSystemctlHangs(t *testing.T) {
	oldExec, oldTimeout := execCommandFn, statusTimeout
	t.Cleanup(func() { execCommandFn, statusTimeout = oldExec, oldTimeout })
	statusTimeout = 150 * time.Millisecond

	calls := 0
	execCommandFn = func(string, ...string) *exec.Cmd {
		calls++
		return exec.Command("sleep", "30")
	}

	start := time.Now()
	got := ListServices()
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("ListServices took %v with a hung systemctl, want about %v", elapsed, statusTimeout)
	}
	if len(got) != 0 {
		t.Errorf("listed %d services from a hung systemctl, want none", len(got))
	}
	if calls != 1 {
		t.Errorf("systemctl was invoked %d times after the first timeout, want the listing to stop at 1", calls)
	}
}

func TestOutputWithinKeepsExitError(t *testing.T) {
	out, err := outputWithin(exec.Command("sh", "-c", "echo hi; exit 3"))
	if string(out) != "hi\n" {
		t.Errorf("stdout = %q, want hi", out)
	}
	var ee *exec.ExitError
	if err == nil || !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Errorf("err = %v, want *exec.ExitError with code 3", err)
	}
}
