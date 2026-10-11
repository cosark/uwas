package middleware

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

// F4600: one IPv6 subscriber owns a /64, so rotating the low bits must not
// give it a fresh bucket per address.
func TestRateLimiterBucketsIPv6ByPrefix(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const limit = 3
	rl := NewRateLimiter(ctx, limit, time.Minute)
	defer rl.Stop()
	allow := func(addr string) bool {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = addr
		return rl.Allow(rl.Key(r))
	}

	allowed := 0
	for i := 0; i < 50; i++ {
		if allow(fmt.Sprintf("[2001:db8:1:2::%x]:1000", i+1)) {
			allowed++
		}
	}
	if allowed != limit {
		t.Errorf("one /64 got %d requests through, want %d", allowed, limit)
	}

	// A neighbouring /64 and an IPv4 client keep their own buckets.
	if !allow("[2001:db8:1:3::1]:1000") {
		t.Error("a different /64 shares the bucket")
	}
	for i := 0; i < limit; i++ {
		if !allow("203.0.113.9:1000") {
			t.Errorf("IPv4 request %d denied", i+1)
		}
	}
	if allow("203.0.113.9:1000") {
		t.Error("IPv4 client not limited after its quota")
	}
}

// F4601: the boolean tautology rules must accept the same inline-comment
// separators as the union/drop rules.
func TestWAFTautologyAcceptsCommentSeparators(t *testing.T) {
	for _, a := range []string{
		"/?id=1 OR/**/1=1",
		"/?id=1' OR/**/'1'='1",
		"/?id=1/**/OR/**/1=1",
		"/?id=1 AND/**/2=2",
		"/?id=1 OR/*!50000*/1=1",
	} {
		if !matchesAny(wafURLPatterns, a) {
			t.Errorf("WAF did not flag %q", a)
		}
	}
	for _, b := range []string{"/?q=cats or dogs", "/?q=rock/**/and roll", "/?note=a /* b */ or c"} {
		if matchesAny(wafURLPatterns, b) {
			t.Errorf("WAF flagged ordinary query %q", b)
		}
	}
}
