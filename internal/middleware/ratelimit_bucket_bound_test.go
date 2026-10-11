package middleware

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func countBuckets(rl *RateLimiter, prefix string) int {
	n := 0
	for i := range rl.shards {
		s := &rl.shards[i]
		s.mu.Lock()
		for k := range s.buckets {
			if strings.HasPrefix(k, prefix) {
				n++
			}
		}
		s.mu.Unlock()
	}
	return n
}

func smallBucketLimiter(t *testing.T, perShard, limit int, window time.Duration) *RateLimiter {
	t.Helper()
	old := maxBucketsPerShard
	maxBucketsPerShard = perShard
	ctx, cancel := context.WithCancel(context.Background())
	rl := NewRateLimiter(ctx, limit, window)
	t.Cleanup(func() {
		rl.Stop()
		cancel()
		maxBucketsPerShard = old
	})
	return rl
}

// F10302: a client rotating a client-chosen key (rate_limit.by: header:X) or
// many source addresses must not grow the bucket table without bound.
func TestRateLimiterBucketTableIsBounded(t *testing.T) {
	const perShard = 4
	rl := smallBucketLimiter(t, perShard, 2, time.Minute)

	// A tracked client is enforced even once the table is full.
	for i := 0; i < 2; i++ {
		if !rl.Allow("keep") {
			t.Fatalf("keep denied within its limit (call %d)", i+1)
		}
	}

	for i := 0; i < 20000; i++ {
		if !rl.Allow(fmt.Sprintf("flood-%d", i)) {
			t.Fatalf("a first request from a new key was denied (flood-%d)", i)
		}
	}
	if got, max := countBuckets(rl, ""), perShard*shardCount; got > max {
		t.Fatalf("bucket table grew to %d, want <= %d", got, max)
	}
	if rl.Allow("keep") {
		t.Fatal("tracked client over its limit was allowed after the table filled")
	}
}

// Expired buckets are evicted when a shard is full, so honest new clients are
// tracked again once the old ones have aged out.
func TestRateLimiterFullShardEvictsExpiredBuckets(t *testing.T) {
	const perShard = 4
	window := time.Minute
	rl := smallBucketLimiter(t, perShard, 2, window)

	for i := 0; i < 20000; i++ {
		rl.Allow(fmt.Sprintf("old-%d", i))
	}
	// Age every bucket past its window.
	for i := range rl.shards {
		s := &rl.shards[i]
		s.mu.Lock()
		for _, b := range s.buckets {
			b.lastReset = time.Now().Add(-2 * window)
		}
		s.swept = time.Time{}
		s.mu.Unlock()
	}
	for i := 0; i < 20000; i++ {
		rl.Allow(fmt.Sprintf("new-%d", i))
	}
	if got := countBuckets(rl, "new-"); got < shardCount {
		t.Fatalf("only %d new buckets tracked after the old ones expired, want >= %d", got, shardCount)
	}
	if got, max := countBuckets(rl, ""), perShard*shardCount; got > max {
		t.Fatalf("bucket table grew to %d, want <= %d", got, max)
	}
}
