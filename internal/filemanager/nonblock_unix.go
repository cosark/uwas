//go:build unix

package filemanager

import "syscall"

// nonBlockFlag keeps open(2) from blocking on a FIFO planted in a web root.
const nonBlockFlag = syscall.O_NONBLOCK

// noFollowFlag makes open(2) refuse a final-component symlink, so a file that
// was swapped for a link after safePathResolved's check is not followed (F6800).
const noFollowFlag = syscall.O_NOFOLLOW
