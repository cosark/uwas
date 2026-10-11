package cache

import (
	"net/http/httptest"
	"testing"
	"time"
)

// F3403: two request paths whose cache keys share an FNV-1a 64 hash (found by a
// rho search over the 16 hex characters after "/c/"). The disk tier used that
// hash as the file name and never compared the stored key, so one URL was
// served the other's response.
func TestDiskCacheKeysWithEqualFNVHashStaySeparate(t *testing.T) {
	key := func(h string) string {
		return GenerateKey(httptest.NewRequest("GET", "http://h.test/c/"+h, nil), nil)
	}
	kA, kB, kC := key("1298570712aef5cc"), key("c87a2f6da0ac3033"), key("0000000000000000")
	if kA == kB || HashKey(kA) != HashKey(kB) || HashKey(kA) == HashKey(kC) {
		t.Fatal("test pair no longer collides under HashKey; the fixture is stale")
	}
	resp := func(body string) *CachedResponse {
		return &CachedResponse{StatusCode: 200, Body: []byte(body), Created: time.Now(), TTL: time.Hour}
	}

	dc := NewDiskCache(t.TempDir(), 1<<20)
	if err := dc.Set(kA, resp("A")); err != nil {
		t.Fatal(err)
	}
	if got, err := dc.Get(kB); err == nil && got != nil {
		t.Fatalf("Get of a never-stored colliding key hit with %q", got.Body)
	}
	if got, err := dc.Get(kC); err == nil && got != nil {
		t.Fatalf("unrelated key hit with %q", got.Body)
	}

	if err := dc.Set(kB, resp("B")); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{kA: "A", kB: "B"} {
		got, err := dc.Get(k)
		if err != nil || got == nil || string(got.Body) != want {
			t.Fatalf("Get(%q) = %v, %v; want body %q", k, got, err, want)
		}
	}

	dc.Delete(kA)
	if got, err := dc.Get(kB); err != nil || got == nil || string(got.Body) != "B" {
		t.Fatalf("Delete of one colliding key removed the other: %v, %v", got, err)
	}
	if got, err := dc.Get(kA); err == nil && got != nil {
		t.Fatal("deleted key still hit")
	}
}
