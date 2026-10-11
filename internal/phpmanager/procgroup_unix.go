//go:build unix

package phpmanager

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// setProcessGroup starts cmd as the leader of its own process group. php-cgi
// and php-fpm run as a master that forks workers (PHP_FCGI_CHILDREN, pool
// children); killing only the master with SIGKILL orphans the workers, which
// keep executing PHP, keep the listen socket and keep the stdout/stderr pipes
// open (F15101).
func setProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// killProcessGroup kills the master and every worker it started. A group that
// is already gone is not an error.
func killProcessGroup(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	// The group id equals the master's pid because setProcessGroup made it the
	// leader; a negative pid addresses the whole group.
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	// ESRCH is ambiguous: no workers are left, or this command is not a group
	// leader (it was not started through setProcessGroup). Either way the
	// master itself still has to go; one that has already been reaped reports
	// os.ErrProcessDone.
	if kerr := cmd.Process.Kill(); kerr != nil && !errors.Is(kerr, os.ErrProcessDone) {
		return kerr
	}
	return nil
}
