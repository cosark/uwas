//go:build unix

package phpmanager

import (
	"fmt"
	"os"
	"syscall"
)

// secureConfDir refuses a config directory this process does not own or that
// others can modify. A missing directory is left to the caller's write to report.
func secureConfDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil
	}
	if !fi.IsDir() {
		return fmt.Errorf("fpm config dir %s is not a directory", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("fpm config dir %s is owned by uid %d, not %d", dir, st.Uid, os.Geteuid())
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("fpm config dir %s is writable by other users (mode %o)", dir, fi.Mode().Perm())
	}
	return nil
}
