package htaccess

import (
	"strings"
	"testing"
)

// TestParseRedirectStatusForms pins Apache mod_alias's Redirect grammar: the
// first argument is a status keyword or number when a status is given, and
// the gone/seeother forms may omit the target entirely. Before the fix the
// 2-arg status forms ("Redirect gone /old") fell into the (pattern, target)
// branch and stored Status=302 with an empty target.
func TestParseRedirectStatusForms(t *testing.T) {
	parse := func(t *testing.T, line string) RedirectRule {
		t.Helper()
		directives, err := Parse(strings.NewReader(line + "\n"))
		if err != nil {
			t.Fatalf("Parse(%q): %v", line, err)
		}
		if len(directives) != 1 {
			t.Fatalf("Parse(%q): %d directives, want 1", line, len(directives))
		}
		isRegex := strings.HasPrefix(directives[0].Name, "RedirectMatch")
		return parseRedirect(directives[0], isRegex)
	}

	cases := []struct {
		name       string
		line       string
		wantStatus int
		wantPat    string
		wantTarget string
	}{
		// Controls — already correct before the fix.
		{"plain two-arg", "Redirect /a /b", 302, "/a", "/b"},
		{"numeric three-arg", "Redirect 301 /a /b", 301, "/a", "/b"},
		{"keyword three-arg", "Redirect permanent /a /b", 301, "/a", "/b"},
		{"numeric gone three-arg", "Redirect 410 /a /b", 410, "/a", "/b"},
		// The misparsed forms.
		{"keyword gone two-arg", "Redirect gone /old-site", 410, "/old-site", ""},
		{"keyword seeother two-arg", "Redirect seeother /moved", 303, "/moved", ""},
		{"match gone two-arg", "RedirectMatch gone ^/gone-page", 410, "^/gone-page", ""},
		{"numeric two-arg keeps number", "Redirect 301 /a", 301, "/a", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := parse(t, tc.line)
			if r.Status != tc.wantStatus {
				t.Errorf("%q: Status = %d, want %d", tc.line, r.Status, tc.wantStatus)
			}
			if r.Pattern != tc.wantPat {
				t.Errorf("%q: Pattern = %q, want %q", tc.line, r.Pattern, tc.wantPat)
			}
			if r.Target != tc.wantTarget {
				t.Errorf("%q: Target = %q, want %q", tc.line, r.Target, tc.wantTarget)
			}
		})
	}
}

// TestParseRedirectStatus300Boundary pins the 300 multiple-choices boundary:
// redirectStatus accepts any 3xx, so a Redirect 300 must keep its numeric
// status instead of falling back to the 302 default. A mutant shifting the
// lower bound to code > 300 survives the suite without this case.
func TestParseRedirectStatus300Boundary(t *testing.T) {
	parse := func(t *testing.T, line string) RedirectRule {
		t.Helper()
		directives, err := Parse(strings.NewReader(line + "\n"))
		if err != nil {
			t.Fatalf("Parse(%q): %v", line, err)
		}
		if len(directives) != 1 {
			t.Fatalf("Parse(%q): %d directives, want 1", line, len(directives))
		}
		isRegex := strings.HasPrefix(directives[0].Name, "RedirectMatch")
		return parseRedirect(directives[0], isRegex)
	}
	r := parse(t, "Redirect 300 /a /b")
	if r.Status != 300 {
		t.Fatalf("Redirect 300: Status = %d, want 300", r.Status)
	}
	if r.Pattern != "/a" || r.Target != "/b" {
		t.Fatalf("Redirect 300: Pattern/Target = %q/%q, want /a and /b", r.Pattern, r.Target)
	}
}
