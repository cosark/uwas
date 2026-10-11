package sftpserver

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// F14602: the first SSH_FXP_READDIR on a handle loaded the whole directory and
// kept every entry until it had been sent, although a reply carries at most
// readDirBatch names, so each OPENDIR+READDIR cost memory proportional to a
// tenant-controlled entry count. Entries are now read one batch at a time.
func TestReadDirIsStreamedInBatches(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	const n = 20000
	for i := 0; i < n; i++ {
		f, err := os.Create(filepath.Join(root, fmt.Sprintf("f%07d", i)))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	rt := pipeSFTP(t, root, false)

	// Completeness: every entry is delivered exactly once, in replies of at
	// most readDirBatch names.
	seen := 0
	h := openDirHandle(t, rt, ".")
	for {
		typ, _, body := rt(sshFXPReadDir, marshalString(h))
		if typ != sshFXPName {
			break
		}
		c := int(binary.BigEndian.Uint32(body[0:4]))
		if c < 1 || c > readDirBatch {
			t.Fatalf("a reply carried %d names; want 1..%d", c, readDirBatch)
		}
		seen += c
	}
	if seen != n {
		t.Fatalf("listed %d names, want %d", seen, n)
	}

	// Cost: the first reply must not pay for the whole directory.
	h2 := openDirHandle(t, rt, ".")
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	if typ, _, _ := rt(sshFXPReadDir, marshalString(h2)); typ != sshFXPName {
		t.Fatalf("first READDIR reply type %d", typ)
	}
	runtime.ReadMemStats(&m1)
	if alloc := m1.TotalAlloc - m0.TotalAlloc; alloc > 1<<20 {
		t.Fatalf("first READDIR on a %d-entry directory allocated %d KiB; want one batch (< 1024 KiB)", n, alloc>>10)
	}
}
