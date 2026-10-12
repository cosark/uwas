package rewrite

import (
	"math/rand"
	"testing"
)

// Seeded table of negated / lookahead pattern combinations against random
// URIs: !MightMatch must imply Process is a no-op (F16600 regression).
func TestMightMatchContractRandomNegatedLookahead(t *testing.T) {
	bodies := []string{
		`/a`, `/admin`, `(?!ok)`, `(?!/ok/)`, `.*\.php$`, `(?!index\.php$).*\.php$`,
		`/(?!x)`, `[a-z]+/`, `(?i)/SECRET`, `(a|b)/c`,
	}
	prefixes := []string{"", "^", "!", "!^", "^/", "!^/"}
	flags := []string{"F", "G", "L", "R=302"}
	alphabet := []string{"/", "a", "b", "c", "ok", "x", "admin", "SECRET", ".php", "index", ".", "z"}
	rng := rand.New(rand.NewSource(16600))
	uris := make([]string, 200)
	for i := range uris {
		n := 1 + rng.Intn(6)
		u := ""
		for j := 0; j < n; j++ {
			u += alphabet[rng.Intn(len(alphabet))]
		}
		uris[i] = u
	}
	checked := 0
	for _, pre := range prefixes {
		for _, b := range bodies {
			for _, f := range flags {
				rule, err := ParseRule(pre+b, "/t", f)
				if err != nil {
					continue
				}
				e := NewEngine([]*Rule{rule})
				for _, uri := range uris {
					if e.MightMatch(uri) {
						continue
					}
					checked++
					res := e.Process(uri, "", &Variables{RequestURI: uri})
					if res.Forbidden || res.Gone || res.Redirect || res.Modified || res.URI != uri {
						t.Fatalf("rule %q [%s]: MightMatch(%q)=false but Process acted: %+v", pre+b, f, uri, res)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no negative MightMatch cases exercised")
	}
}
