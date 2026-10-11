package htaccess

import (
	"bytes"
	"net"
	"runtime"
	"strings"
	"testing"
)

// F14200: .htaccess regexes are compiled for every request, and the 4 KiB line
// limit still admits a 570k-instruction program (".{1000}" x 570: ~750 ms and
// ~280 MiB per request). Oversized patterns are now refused like any other
// pattern RE2 cannot compile, so a request costs a cache lookup.
func TestOversizedHtaccessRegexCostsNothingPerRequest(t *testing.T) {
	heavy := strings.Repeat(`.{1000}`, 570)
	src := "RedirectMatch 301 " + heavy + " /x\n<FilesMatch \"" + heavy + "\">\nRequire all denied\n</FilesMatch>\n"
	d, err := Parse(bytes.NewReader([]byte(src)))
	if err != nil {
		t.Fatal(err)
	}
	rs := Convert(d)
	if len(rs.Redirects) != 1 || len(rs.FilesMatch) != 1 {
		t.Fatalf("setup: %d redirects, %d FilesMatch blocks", len(rs.Redirects), len(rs.FilesMatch))
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < 5; i++ {
		_, _, _ = MatchRedirect(rs.Redirects[0], "/a/b.jpg")
		_ = FilesMatchDeniesForRequest(rs, "a.jpg", net.ParseIP("203.0.113.9"), "GET", nil)
	}
	runtime.ReadMemStats(&after)
	if mib := (after.TotalAlloc - before.TotalAlloc) >> 20; mib > 16 {
		t.Errorf("5 requests allocated %d MiB; an oversized pattern must not be recompiled per request", mib)
	}
}

// An oversized pattern behaves like an uncompilable one: a redirect is skipped,
// and a <FilesMatch> that carries a deny keeps denying (fail closed).
func TestOversizedHtaccessRegexFailsLikeAnUncompilableOne(t *testing.T) {
	heavy := strings.Repeat(`.{1000}`, 570)
	if _, _, ok := MatchRedirect(RedirectRule{Status: 301, Pattern: heavy, Target: "/x", IsRegex: true}, "/a"); ok {
		t.Error("an oversized RedirectMatch must not match")
	}
	d, err := Parse(bytes.NewReader([]byte("<FilesMatch \"" + heavy + "\">\nRequire all denied\n</FilesMatch>\n")))
	if err != nil {
		t.Fatal(err)
	}
	rs := Convert(d)
	if !FilesMatchDeniesForRequest(rs, "any.txt", net.ParseIP("203.0.113.9"), "GET", nil) {
		t.Error("an oversized <FilesMatch> with a deny must keep denying")
	}
}

// Control: ordinary and large-but-realistic patterns are unaffected.
func TestRealisticHtaccessRegexesStillWork(t *testing.T) {
	var names []string
	for i := 0; i < 300; i++ {
		names = append(names, "badbot"+strings.Repeat("x", i%7)+string(rune('a'+i%26)))
	}
	list := "(" + strings.Join(names, "|") + ")"
	if loc, status, ok := MatchRedirect(RedirectRule{Status: 301, Pattern: `^/old/(.*)$`, Target: "/new/$1", IsRegex: true}, "/old/page"); !ok || status != 301 || loc != "/new/page" {
		t.Errorf("RedirectMatch: %q %d %v", loc, status, ok)
	}
	d, err := Parse(bytes.NewReader([]byte("<FilesMatch \"" + list + "\">\nRequire all denied\n</FilesMatch>\n")))
	if err != nil {
		t.Fatal(err)
	}
	rs := Convert(d)
	if !FilesMatchDeniesForRequest(rs, "badbotxa", net.ParseIP("203.0.113.9"), "GET", nil) {
		t.Error("a realistic 300-name FilesMatch must still match")
	}
	if FilesMatchDeniesForRequest(rs, "index.html", net.ParseIP("203.0.113.9"), "GET", nil) {
		t.Error("a non-matching file must not be denied")
	}
}
