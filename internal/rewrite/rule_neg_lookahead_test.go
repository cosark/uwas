package rewrite

import "testing"

// F6100: a RewriteRule whose pattern begins with a PCRE negative lookahead
// failed to compile under RE2 and was dropped, so an [F] guard such as
// "^(?!index\.php$).*\.php$" blocked nothing.
func TestParseRuleLeadingNegativeLookahead(t *testing.T) {
	r, err := ParseRule(`^(?!index\.php$).*\.php$`, "-", "F")
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	for uri, want := range map[string]bool{
		"uploads/shell.php": true,
		"shell.php":         true,
		"index.php":         false, // vetoed by the lookahead
		"readme.txt":        false, // control: not a .php file
	} {
		if got, _ := r.Match(uri); got != want {
			t.Errorf("Match(%q) = %v, want %v", uri, got, want)
		}
	}

	nc, err := ParseRule(`^(?!ADMIN/).*$`, "-", "NC,F")
	if err != nil {
		t.Fatalf("ParseRule NC: %v", err)
	}
	if got, _ := nc.Match("admin/x"); got {
		t.Error("NC lookahead did not veto admin/x")
	}
	if got, _ := nc.Match("pub/x"); !got {
		t.Error("pub/x should match")
	}

	neg, err := ParseRule(`!^(?!pub/).*$`, "-", "F")
	if err != nil {
		t.Fatalf("ParseRule negated: %v", err)
	}
	if got, _ := neg.Match("pub/x"); !got { // inner pattern vetoed -> negation holds
		t.Error("negated rule should match pub/x")
	}
}

func TestParseRuleUnsupportedLookaheadStillErrors(t *testing.T) {
	for _, p := range []string{
		`^(?!(a)b)c`,   // capture group inside the lookahead
		`^(?=a)b`,      // positive lookahead
		`^a(?!b)`,      // not leading
		`^(?!a(?!b))c`, // nested lookahead
		`^(?!a`,        // unterminated
	} {
		if _, err := ParseRule(p, "-", "F"); err == nil {
			t.Errorf("ParseRule(%q) compiled, want the original error", p)
		}
	}
}
