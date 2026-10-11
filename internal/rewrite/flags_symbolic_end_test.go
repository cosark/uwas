package rewrite

import "testing"

// F6402: Apache accepts symbolic redirect statuses and the [END] flag.
func TestParseFlagsSymbolicRedirectAndEnd(t *testing.T) {
	for _, c := range []struct {
		flags string
		want  int
	}{
		{"R=301,L", 301},
		{"R=permanent,L", 301},
		{"R=PERMANENT", 301},
		{"R=temp", 302},
		{"R=seeother", 303},
		{"R=308", 308},
		{"R=bogus", 302},
		{"R", 302},
	} {
		if got := ParseFlags(c.flags).Redirect; got != c.want {
			t.Errorf("ParseFlags(%q).Redirect = %d, want %d", c.flags, got, c.want)
		}
	}
	if !ParseFlags("END").Last || !ParseFlags("NC,end").Last {
		t.Error("[END] must end the rule pass like [L]")
	}
	if ParseFlags("E=A:b").Last {
		t.Error("[E=..] alone must not end the rule pass")
	}
}
