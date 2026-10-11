package pathmatch

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// F14401: location and cache-rule regexes are tenant-settable and run on every
// request path; their compiled size is bounded and the compiled cache cannot
// grow without limit.
func TestRegexProgramSizeIsBounded(t *testing.T) {
	heavy := strings.Repeat("(?:.{100})?", 120) + "x"                             // ~12k instructions
	huge := strings.Repeat(".{1000}", 570)                                        // ~570k instructions
	manyExt := "\\.(" + strings.Repeat("jpg|png|gif|css|js|woff2|", 30) + "svg)$" // a long but ordinary list
	for _, tc := range []struct {
		name, expr string
		ok         bool
	}{
		{"prefix", "^/api/", true},
		{"extension list", `\.(jpg|jpeg|png|gif|css|js|woff2?|ttf|svg|ico|webp)$`, true},
		{"long extension alternation", manyExt, true},
		{"12k instructions", heavy, false},
		{"570k instructions", huge, false},
		{"does not compile", "(", false},
	} {
		if err := ValidRegex(tc.expr); (err == nil) != tc.ok {
			t.Errorf("%s: ValidRegex err = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
	if ValidLocation("~"+heavy) == nil {
		t.Error("ValidLocation accepted a 12k-instruction regex")
	}
	if ValidLocation("/api/") != nil || ValidLocation("~^/api/") != nil {
		t.Error("ValidLocation rejected an ordinary location")
	}
}

// A refused pattern never matches and costs nothing per request.
func TestRefusedRegexNeverMatchesAndIsCheap(t *testing.T) {
	heavy := "~" + strings.Repeat("(?:.{100})?", 120) + "x"
	path := "/" + strings.Repeat("a", 4000) + "x"
	Location("/warm", heavy)
	start := time.Now()
	for i := 0; i < 50; i++ {
		if Location(path, heavy) || Regex(path, strings.TrimPrefix(heavy, "~")) {
			t.Fatal("a refused pattern matched")
		}
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("50 matches of a refused pattern took %v", d)
	}
	if !Location("/api/x", "~^/api/") {
		t.Error("control: an ordinary regex stopped matching")
	}
}

func TestRegexCacheIsBounded(t *testing.T) {
	for i := 0; i < 3*maxRegexCache; i++ {
		Location("/x", fmt.Sprintf("~^/bound%d/", i))
	}
	n := 0
	regexCache.Range(func(_, _ any) bool { n++; return true })
	if n > maxRegexCache+8 {
		t.Errorf("%d compiled patterns cached, want <= %d", n, maxRegexCache)
	}
	if !Location("/bound5/y", "~^/bound5/") {
		t.Error("a pattern evicted from the cache stopped matching")
	}
}
