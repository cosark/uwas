package rewrite

import "testing"

// MightMatch is the engine's cheap pre-check: the server skips Process
// entirely when it says no. So "no" must mean that Process would change
// nothing and refuse nothing for that URI; a "no" that Process disagrees with
// skips every rule, [F] guards included (R125).
func TestMightMatchNeverSaysNoWhereProcessActs(t *testing.T) {
	type spec struct{ pattern, target, flags string }
	specs := []spec{
		{`^/admin`, "-", "F"},
		{`^admin`, "-", "F"},
		{`!^/public/`, "-", "F"},
		{`^(?!index\.php$).*\.php$`, "-", "F"},
		{`!^(?!index\.php$).*\.php$`, "-", "F"},
		{`^(?!/index\.php$).*\.php$`, "-", "F"},
		{`!^(?!/index\.php$).*\.php$`, "-", "F"},
		{`!^(?!/ok/).*\.php$`, "-", "F"},
		{`!^/(?!ok/).*$`, "-", "F"},
		{`^/a(?!b)`, "/z", "L"},
		{`!^/a(?!b)`, "/z", "L"},
		{`(?i)^/SECRET`, "-", "F"},
		{`\.(bak|old)$`, "-", "G"},
		{`!\.(html|css)$`, "-", "F"},
	}
	uris := []string{
		"/", "/admin", "/admin/x", "admin", "index.php", "/index.php", "/a.php", "/x/index.php", "/ok/y.php",
		"/public/a", "/private/a", "/ab", "/ac", "/a", "/secret", "/SECRET/x", "/x.bak", "/x.html", "/x.css", "/x.txt",
	}
	for _, s := range specs {
		rule, err := ParseRule(s.pattern, s.target, s.flags)
		if err != nil {
			t.Logf("skipping %q: %v", s.pattern, err)
			continue
		}
		e := NewEngine([]*Rule{rule})
		for _, uri := range uris {
			if e.MightMatch(uri) {
				continue
			}
			vars := &Variables{RequestURI: uri}
			res := e.Process(uri, "", vars)
			if res.Forbidden || res.Gone || res.Redirect || res.Modified || res.URI != uri {
				t.Errorf("rule %q (%s): MightMatch(%q) = false but Process acted: forbidden=%v gone=%v redirect=%v uri=%q",
					s.pattern, s.flags, uri, res.Forbidden, res.Gone, res.Redirect, res.URI)
			}
		}
	}
}
