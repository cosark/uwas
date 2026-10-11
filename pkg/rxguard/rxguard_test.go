package rxguard

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestHeavyPatternsAreRejected(t *testing.T) {
	for name, p := range map[string]string{
		"repeated .{1000}":    strings.Repeat(`.{1000}`, 570),
		"concatenated x{999}": strings.Repeat(`a{999}`, 20),
		"repeat of group":     `(abcdefghij){900}(klmnopqrst){900}`,
	} {
		re, err := Compile(p)
		if re != nil || !errors.Is(err, ErrTooComplex) {
			t.Errorf("%s: got re=%v err=%v, want ErrTooComplex", name, re != nil, err)
		}
	}
}

// Real .htaccess patterns must keep compiling: a few hundred bot names, a
// long extension list, case-insensitive and anchored forms.
func TestRealisticPatternsAreAccepted(t *testing.T) {
	var bots []string
	for i := 0; i < 300; i++ {
		bots = append(bots, fmt.Sprintf("badbot%03dxx", i))
	}
	for name, p := range map[string]string{
		"bot list":     "(?i)(" + strings.Join(bots, "|") + ")",
		"extensions":   `\.(jpg|jpeg|png|gif|svg|webp|avif|ico|css|js|woff2?|ttf|eot|map)$`,
		"wordpress":    `^/wp-(admin|includes|content)/.*\.php$`,
		"small repeat": `^[a-z0-9]{1,64}$`,
		"ip":           `^(\d{1,3}\.){3}\d{1,3}$`,
		"moderate rep": `a{100}b{100}`,
	} {
		re, err := Compile(p)
		if err != nil || re == nil {
			t.Errorf("%s: rejected: %v", name, err)
		}
	}
}

func TestInvalidSyntaxStillReportsError(t *testing.T) {
	for _, p := range []string{`(`, `[a-`, `*a`, `a{2,1}`} {
		if re, err := Compile(p); re != nil || err == nil {
			t.Errorf("%q: got re=%v err=%v, want a syntax error", p, re != nil, err)
		}
	}
}

func TestResultsAreCachedAndShared(t *testing.T) {
	a, _ := Compile(`^/cached/(.*)$`)
	b, _ := Compile(`^/cached/(.*)$`)
	if a == nil || a != b {
		t.Error("the same pattern must return the same compiled regexp")
	}
	_, e1 := Compile(strings.Repeat(`.{1000}`, 570))
	_, e2 := Compile(strings.Repeat(`.{1000}`, 570))
	if !errors.Is(e1, ErrTooComplex) || !errors.Is(e2, ErrTooComplex) {
		t.Error("a rejected pattern must stay rejected")
	}
}

func TestCacheIsBounded(t *testing.T) {
	for i := 0; i < maxCached*3; i++ {
		if _, err := Compile(fmt.Sprintf("^/bounded/%d$", i)); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	n := len(cache)
	mu.Unlock()
	if n > maxCached {
		t.Errorf("cache holds %d entries, cap is %d", n, maxCached)
	}
}

func TestConcurrentCompile(t *testing.T) {
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				re, err := Compile(fmt.Sprintf("^/c/%d$", (i+g)%40))
				if err != nil || !re.MatchString(fmt.Sprintf("/c/%d", (i+g)%40)) {
					t.Errorf("bad compile result: %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}
