package cache

import (
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// F14704: DiskLimit is charged in whole filesystem blocks. A file counted at
// its length made an entry of a few hundred bytes cost a tenth of the 4 KiB it
// holds, so many small entries filled the disk to many times the limit.
func TestDiskCacheChargesWholeBlocks(t *testing.T) {
	dir := t.TempDir()
	const limit = 10 * diskBlockSize
	dc := NewDiskCache(dir, limit)

	tiny := func() *CachedResponse {
		return &CachedResponse{
			StatusCode: 404,
			Headers:    http.Header{"Content-Type": {"text/plain"}},
			Body:       make([]byte, 100),
			Created:    time.Now(),
			TTL:        time.Hour,
		}
	}
	files := func() int {
		n := 0
		filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && filepath.Ext(p) == ".cache" {
				n++
			}
			return nil
		})
		return n
	}

	for i := 0; i < 50; i++ {
		if err := dc.Set(fmt.Sprintf("/small/%d", i), tiny()); err != nil {
			t.Fatal(err)
		}
	}
	if got := files(); got != 10 {
		t.Errorf("%d entries written against a limit of 10 blocks, want 10", got)
	}
	if used := dc.usedBytes.Load(); used != limit {
		t.Errorf("usedBytes = %d, want %d (ten whole blocks)", used, limit)
	}

	// Deleting one frees its block, and a restart finds the same total.
	var kept string
	for i := 0; i < 50; i++ {
		k := fmt.Sprintf("/small/%d", i)
		if _, err := dc.Get(k); err == nil {
			kept = k
			break
		}
	}
	dc.Delete(kept)
	if used := dc.usedBytes.Load(); used != limit-diskBlockSize {
		t.Errorf("usedBytes = %d after one delete, want %d", used, limit-diskBlockSize)
	}
	if got := NewDiskCache(dir, limit).usedBytes.Load(); got != limit-diskBlockSize {
		t.Errorf("a restart counted %d bytes, want %d", got, limit-diskBlockSize)
	}

	if diskCost(0) != 0 || diskCost(1) != diskBlockSize || diskCost(diskBlockSize) != diskBlockSize || diskCost(diskBlockSize+1) != 2*diskBlockSize {
		t.Errorf("diskCost rounds wrongly: 0->%d 1->%d 4096->%d 4097->%d", diskCost(0), diskCost(1), diskCost(diskBlockSize), diskCost(diskBlockSize+1))
	}
}
