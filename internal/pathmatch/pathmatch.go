// Package pathmatch holds the two URL-path matchers UWAS applies to
// per-domain configuration: location patterns and cache-rule regexes.
//
// They live in their own package because both the request path and the admin
// API need them, and the admin package cannot import the server package —
// the server constructs the admin server, so the dependency only runs one
// way. Duplicating the matchers instead would let the panel's answer drift
// away from what the server actually does.
package pathmatch

import (
	"path"
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/uwaserver/uwas/pkg/rxguard"
)

// Clean returns the canonical form of a request path: dot segments and
// repeated slashes resolved, a trailing slash kept. The static handler opens
// files through filepath.Clean, so "//private/x" and "/a/../private/x" reach
// the same file as "/private/x"; a rule that decides on the path as sent
// (a location's basic_auth, a WAF bypass prefix) must decide on this form or
// the rule can be skipped while the file is still served (F2500).
func Clean(p string) string {
	if p == "" || p[0] != '/' {
		return p
	}
	c := path.Clean(p)
	if c != p && c != "/" && strings.HasSuffix(p, "/") {
		c += "/"
	}
	return c
}

// MaxRegexInstructions bounds the compiled size of a location or cache-rule
// regex. A tenant can set these patterns (a reseller edits locations[].match
// and cache.rules[].match of their own domains) and every request path is run
// through them. Go's regexp costs about program size x input length x 10 ns,
// so a pattern of a few hundred thousand instructions took 16 s to match a
// 2 KB URL, and one of 12k instructions ~0.1 ms per path byte. Real patterns
// ("^/api/", a list of file extensions) are a few dozen to a few hundred
// instructions (F14401).
const MaxRegexInstructions = 1000

// maxRegexCache bounds the compiled patterns kept. Patterns come from config,
// but a reseller can change them over the admin API as often as they like, so
// the cache cannot simply grow with every distinct string.
const maxRegexCache = 1024

// compileRegex is regexp.Compile with the size bound: rxguard rejects what is
// far too large without compiling it, and the exact program size is checked
// against MaxRegexInstructions.
func compileRegex(expr string) (*regexp.Regexp, error) {
	re, err := rxguard.Compile(expr)
	if err != nil {
		return nil, err
	}
	if programSize(expr) > MaxRegexInstructions {
		return nil, rxguard.ErrTooComplex
	}
	return re, nil
}

// programSize is the number of instructions regexp compiles expr to.
func programSize(expr string) int {
	parsed, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return 0
	}
	prog, err := syntax.Compile(parsed.Simplify())
	if err != nil {
		return 0
	}
	return len(prog.Inst)
}

// regexCache keeps compiled patterns so a request never pays for a recompile.
var (
	regexCache    sync.Map
	regexCacheLen atomic.Int64
)

func compile(pattern string) *regexp.Regexp {
	if v, ok := regexCache.Load(pattern); ok {
		return v.(*regexp.Regexp)
	}
	re, err := compileRegex(pattern)
	if err != nil {
		re = nil
	}
	if regexCacheLen.Add(1) > maxRegexCache {
		regexCache.Range(func(k, _ any) bool { regexCache.Delete(k); return true })
		regexCacheLen.Store(1)
	}
	regexCache.Store(pattern, re)
	return re
}

// ValidRegex reports why a regular expression from configuration cannot be
// used: it does not compile, or it is larger than MaxRegexInstructions.
func ValidRegex(expr string) error {
	_, err := compileRegex(expr)
	return err
}

// Regex reports whether a path matches a cache-rule pattern, which is always
// a regular expression. An uncompilable pattern never matches; config
// validation warns about those separately.
//
// The path is matched in canonical form (Clean): a cache bypass rule for
// "^/cart" must also cover "//cart/x", which is served as "/cart/x" (F2531).
func Regex(path, pattern string) bool {
	re := compile(pattern)
	return re != nil && re.MatchString(Clean(path))
}

// Location reports whether a path matches a location pattern. A leading "~"
// marks a regex, as in nginx; anything else is a prefix.
//
// An empty pattern is UNSET, not a wildcard. strings.HasPrefix(path, "") is
// true for every path, so without this guard a location block with no match
// became a domain-wide catch-all: it applied its headers and Cache-Control to
// every request and, because callers break on first match, suppressed every
// location block after it. config validation treats an empty match as absent
// (validate.go guards `if loc.Match != ""`), and the rewrite engine drops a
// rule whose pattern will not parse rather than applying it everywhere — an
// unset match does the same here.
func Location(path, pattern string) bool {
	if pattern == "" {
		return false
	}
	path = Clean(path)
	if expr, isRegex := locationRegex(pattern); isRegex {
		re := compile(expr)
		return re != nil && re.MatchString(path)
	}
	return strings.HasPrefix(path, pattern)
}

// locationRegex returns the regular expression a "~" or "~*" location pattern
// stands for. "~*" is nginx's case-insensitive form; read as the plain "~" form
// its leading "*" made the expression uncompilable, so the location never
// matched and its basic_auth or rate_limit silently never applied (F3301).
func locationRegex(pattern string) (string, bool) {
	rest, ok := strings.CutPrefix(pattern, "~")
	if !ok {
		return "", false
	}
	if ci, ok := strings.CutPrefix(rest, "*"); ok {
		return "(?i)" + strings.TrimSpace(ci), true
	}
	return strings.TrimSpace(rest), true
}

// ValidLocation reports why a location pattern can never match: a "~" pattern
// whose regular expression does not compile. Prefix patterns always pass.
func ValidLocation(pattern string) error {
	if expr, isRegex := locationRegex(pattern); isRegex {
		return ValidRegex(expr)
	}
	return nil
}
