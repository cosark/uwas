package cache

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

func oversizeResp(n int) *CachedResponse {
	return &CachedResponse{StatusCode: 200, Headers: http.Header{}, Body: make([]byte, n), Created: time.Now(), TTL: time.Hour}
}

// F18900: an entry larger than the whole memory limit can never be stored, so
// setting one must not evict the entries already cached in its shard.
func TestMemorySetOversizeEntryEvictsNothing(t *testing.T) {
	const limit = 100_000
	mc := NewMemoryCache(limit)
	for i := 0; i < 60; i++ {
		mc.Set(fmt.Sprintf("k%d", i), oversizeResp(100))
	}
	before := mc.Len()
	used := mc.usedBytes.Load()
	for i := 0; i < 500; i++ {
		mc.Set(fmt.Sprintf("huge%d", i), oversizeResp(limit*2))
	}
	if got := mc.Len(); got != before {
		t.Fatalf("oversize sets changed entry count %d -> %d", before, got)
	}
	if got := mc.usedBytes.Load(); got != used {
		t.Fatalf("usedBytes %d -> %d", used, got)
	}
	// An oversize replacement of an existing key drops the stale value.
	mc.Set("k0", oversizeResp(limit*2))
	if r, _ := mc.Get("k0"); r != nil {
		t.Fatal("stale k0 still served after oversize replacement")
	}
	// Control: an entry that fits is still stored.
	mc.Set("fits", oversizeResp(100))
	if r, _ := mc.Get("fits"); r == nil {
		t.Fatal("fitting entry not stored")
	}
}
