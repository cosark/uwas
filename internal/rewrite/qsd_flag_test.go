package rewrite

import "testing"

// F6701: [QSD] discards the incoming query string; it was ignored, so
// `RewriteRule ^old$ /new [R=301,QSD]` leaked "?token=secret" into Location.
func TestQSDDiscardsIncomingQuery(t *testing.T) {
	run := func(target, flags, query string) *Result {
		r, err := ParseRule("^/old$", target, flags)
		if err != nil {
			t.Fatal(err)
		}
		return NewEngine([]*Rule{r}).Process("/old", query, &Variables{RequestURI: "/old", QueryString: query})
	}
	cases := []struct {
		name, target, flags, query string
		wantURI, wantQuery         string
	}{
		{"control keeps query", "/new", "R=301,L", "token=secret", "/new?token=secret", "token=secret"},
		{"QSD redirect", "/new", "R=301,QSD,L", "token=secret", "/new", ""},
		{"QSD rewrite", "/new", "QSD,L", "token=secret", "/new", ""},
		{"QSD keeps substitution's own query", "/new?x=1", "QSD,L", "token=secret", "/new", "x=1"},
		{"QSD wins over QSA", "/new?x=1", "QSA,QSD,L", "token=secret", "/new", "x=1"},
		{"QSA appends", "/new?x=1", "QSA,L", "token=secret", "/new", "x=1&token=secret"},
		{"QSD with no query is a no-op", "/new", "QSD,L", "", "/new", ""},
	}
	for _, c := range cases {
		res := run(c.target, c.flags, c.query)
		if res.URI != c.wantURI && !(res.Redirect && res.URI == c.wantURI) {
			t.Errorf("%s: URI %q, want %q", c.name, res.URI, c.wantURI)
		}
		if !res.Redirect && res.Query != c.wantQuery {
			t.Errorf("%s: Query %q, want %q", c.name, res.Query, c.wantQuery)
		}
	}
}
