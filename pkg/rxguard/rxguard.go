// Package rxguard compiles regular expressions that come from tenant-written
// configuration (.htaccess, rewrite rules) with a bound on the size of the
// program they compile to.
//
// Go's regexp matches in linear time, but it compiles "x{1000}" into a
// thousand copies of x. A 4 KiB pattern such as ".{1000}" repeated 570 times
// is a valid program of ~570k instructions: ~750 ms and ~280 MiB of garbage
// to compile. .htaccess patterns used to be compiled on every request, so one
// tenant could pin the whole server with a few requests (F14200).
package rxguard

import (
	"errors"
	"regexp"
	"regexp/syntax"
	"sync"
)

// MaxInstructions bounds the estimated size of a compiled pattern. Real
// .htaccess patterns (a list of a few hundred bot names, a long extension
// list) stay well below it.
const MaxInstructions = 10000

// maxCached bounds how many compiled patterns are kept for reuse.
const maxCached = 512

// ErrTooComplex is returned for a pattern whose compiled program would exceed
// MaxInstructions.
var ErrTooComplex = errors.New("regular expression too complex")

type entry struct {
	re  *regexp.Regexp
	err error
}

var (
	mu    sync.Mutex
	cache = make(map[string]entry, 64)
)

// Compile is regexp.Compile with a size bound and a bounded cache of results,
// failures included: a pattern that cannot be compiled is the same on every
// request, and re-parsing a multi-kilobyte one each time is itself a cost.
// The returned *regexp.Regexp is shared and safe for concurrent use.
func Compile(pattern string) (*regexp.Regexp, error) {
	mu.Lock()
	e, ok := cache[pattern]
	mu.Unlock()
	if ok {
		return e.re, e.err
	}

	e = compile(pattern)

	mu.Lock()
	if len(cache) >= maxCached {
		cache = make(map[string]entry, 64)
	}
	cache[pattern] = e
	mu.Unlock()
	return e.re, e.err
}

func compile(pattern string) entry {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		// Let regexp report the error in its own words.
		re, err := regexp.Compile(pattern)
		return entry{re, err}
	}
	if cost(parsed) > MaxInstructions {
		return entry{nil, ErrTooComplex}
	}
	re, err := regexp.Compile(pattern)
	return entry{re, err}
}

const satLimit = int64(1) << 40

func sat(n int64) int64 {
	if n > satLimit {
		return satLimit
	}
	return n
}

// cost estimates the instruction count of a parsed pattern, counting a
// repetition x{n,m} as max(n, m) copies of x (what regexp compiles it to).
func cost(re *syntax.Regexp) int64 {
	switch re.Op {
	case syntax.OpLiteral:
		return sat(int64(len(re.Rune)))
	case syntax.OpConcat:
		var n int64
		for _, s := range re.Sub {
			n = sat(n + cost(s))
		}
		return n
	case syntax.OpAlternate:
		n := int64(len(re.Sub))
		for _, s := range re.Sub {
			n = sat(n + cost(s))
		}
		return n
	case syntax.OpCapture, syntax.OpStar, syntax.OpPlus, syntax.OpQuest:
		return sat(cost(re.Sub[0]) + 2)
	case syntax.OpRepeat:
		copies := int64(re.Max)
		if re.Max < 0 {
			copies = int64(re.Min) + 1
		}
		if copies < 1 {
			copies = 1
		}
		return sat(cost(re.Sub[0])*copies + 2)
	default:
		return 1
	}
}
