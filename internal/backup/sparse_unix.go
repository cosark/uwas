//go:build unix

package backup

import (
	"os"
	"syscall"
)

// allocatedBytes reports how many bytes the file really occupies on disk.
func allocatedBytes(info os.FileInfo) (int64, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int64(st.Blocks) * 512, true
}
