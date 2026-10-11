package cache

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// F14700: an entry is charged for its key and its bookkeeping, not just its
// body and headers. A key can be a URL with a long query string, and an entry
// with a tiny body used to count at a tenth of the memory it held, so a client
// could keep far more alive than MemoryLimit.
func TestMemoryCacheChargesKeyAndBookkeeping(t *testing.T) {
	const limit = 4 << 20
	small := func(bodyLen int) *CachedResponse {
		return &CachedResponse{
			StatusCode: 404,
			Headers:    http.Header{"Content-Type": {"text/plain"}},
			Body:       make([]byte, bodyLen),
			Created:    time.Now(),
			TTL:        time.Minute,
		}
	}

	t.Run("long keys are bounded by the limit", func(t *testing.T) {
		mc := NewMemoryCache(limit)
		pad := strings.Repeat("k", 64<<10)
		for i := 0; i < 2000; i++ {
			mc.Set(fmt.Sprintf("%08d", i)+pad, small(16))
		}
		// Each entry holds a 64 KiB key, so no more than limit/64KiB fit.
		if got, max := mc.Len(), limit/(64<<10); got > max {
			t.Errorf("%d entries with 64 KiB keys held against a %d byte limit, want at most %d", got, limit, max)
		}
		if _, _, _, used := mc.Stats(); used > limit {
			t.Errorf("accounted %d bytes, over the %d byte limit", used, limit)
		}
	})

	t.Run("a tiny entry is charged more than its payload", func(t *testing.T) {
		mc := NewMemoryCache(limit)
		mc.Set("k", small(16))
		if _, _, _, used := mc.Stats(); used < 512 {
			t.Errorf("a one-header entry is charged %d bytes, want at least the per-entry bookkeeping", used)
		}
	})

	t.Run("ordinary entries still fit (control)", func(t *testing.T) {
		mc := NewMemoryCache(limit)
		for i := 0; i < 3000; i++ {
			mc.Set(fmt.Sprintf("/page/%d", i), small(100))
		}
		if got := mc.Len(); got != 3000 {
			t.Errorf("%d of 3000 small entries kept, want all", got)
		}
	})

	t.Run("replacing a key releases its old charge", func(t *testing.T) {
		mc := NewMemoryCache(limit)
		mc.Set("same", small(1000))
		_, _, _, first := mc.Stats()
		for i := 0; i < 100; i++ {
			mc.Set("same", small(1000))
		}
		if _, _, _, used := mc.Stats(); used != first {
			t.Errorf("used = %d after 100 overwrites, want %d", used, first)
		}
	})
}
