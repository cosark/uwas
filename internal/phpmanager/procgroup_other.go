//go:build !unix

package phpmanager

import (
	"errors"
	"os"
	"os/exec"
)

// There are no process groups to address outside unix; the master is killed.
func setProcessGroup(cmd *exec.Cmd) {}

func killProcessGroup(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}
