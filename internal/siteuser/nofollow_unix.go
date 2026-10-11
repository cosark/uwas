//go:build unix

package siteuser

import "syscall"

// noFollowFlag makes open(2) refuse a final-component symlink. The tenant owns
// its .ssh directory, so authorized_keys there can be swapped for a link to a
// file only root may write.
const noFollowFlag = syscall.O_NOFOLLOW

// noBlockFlag keeps open(2) from waiting on a FIFO planted at the path.
const noBlockFlag = syscall.O_NONBLOCK
