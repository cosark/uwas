package htaccess

import (
	"strings"
	"testing"
)

func boolStr(b *bool) string {
	switch {
	case b == nil:
		return "nil"
	case *b:
		return "true"
	}
	return "false"
}

// F9400: an Options list with an unsigned option is absolute and replaces the
// inherited options, so unless it names Indexes the listing is off. It used to be
// ignored and the listing stayed as the domain config or a parent file had it.
func TestOptionsAbsoluteListSwitchesIndexesOff(t *testing.T) {
	cases := []struct{ src, want string }{
		{"Options -Indexes\n", "false"},
		{"Options +Indexes\n", "true"},
		{"Options Indexes FollowSymLinks\n", "true"},
		{"Options +FollowSymLinks\n", "nil"}, // relative: leaves Indexes alone
		{"Options -Indexes +FollowSymLinks\n", "false"},
		{"Options None\n", "false"},
		{"Options FollowSymLinks\n", "false"},
		{"Options SymLinksIfOwnerMatch\n", "false"},
		{"Options All\n", "nil"}, // never widens a listing on its own
	}
	for _, c := range cases {
		if got := boolStr(convertSrc(t, c.src).DirectoryListing); got != c.want {
			t.Errorf("%q: DirectoryListing = %s, want %s", strings.TrimSpace(c.src), got, c.want)
		}
	}
}

// F9401: a double-quoted ErrorDocument argument is message text in Apache; a
// path, a URL and an unquoted word are not.
func TestErrorDocumentQuotedTextIsRecorded(t *testing.T) {
	rs := convertSrc(t, "ErrorDocument 404 \"Custom not found\"\n"+
		"ErrorDocument 403 /err/403.html\n"+
		"ErrorDocument 410 \"/err/410.html\"\n"+
		"ErrorDocument 500 'single quoted'\n"+
		"ErrorDocument 503 http://example.com/down\n")
	if got := rs.ErrorTexts[404]; got != "Custom not found" {
		t.Errorf("404 text = %q, want the message", got)
	}
	for _, code := range []int{403, 410, 500, 503} {
		if txt, ok := rs.ErrorTexts[code]; ok {
			t.Errorf("code %d recorded as text %q, want a path/URL entry only", code, txt)
		}
		if rs.ErrorDocuments[code] == "" {
			t.Errorf("code %d lost its ErrorDocuments entry", code)
		}
	}
	if rs.ErrorDocuments[404] != "Custom not found" {
		t.Errorf("ErrorDocuments[404] = %q, want the text kept for path-only readers", rs.ErrorDocuments[404])
	}
	// A later path directive for the same code replaces the text.
	rs = convertSrc(t, "ErrorDocument 404 \"msg\"\nErrorDocument 404 /e.html\n")
	if _, ok := rs.ErrorTexts[404]; ok {
		t.Error("a later path ErrorDocument must clear the earlier text")
	}
}

// F9402: per-directory settings follow the chain, the deepest file wins and
// ExpiresActive Off below switches an inherited On off.
func TestDirSettingsFollowTheChain(t *testing.T) {
	root := convertSrc(t, "AddType application/x-root .rt\nAddType application/x-both .both\n"+
		"ExpiresActive On\nExpiresByType text/plain \"access plus 1 hour\"\nDirectoryIndex index.html\n")
	sub := convertSrc(t, "AddType application/x-sub .sub\nAddType application/x-sub-both .both\n"+
		"ExpiresDefault \"access plus 1 day\"\nDirectoryIndex home.txt\nErrorDocument 404 \"sub text\"\n")
	off := convertSrc(t, "ExpiresActive Off\n")

	eff := DirSettings([]*RuleSet{root, nil, sub})
	if eff.MimeTypes[".rt"] != "application/x-root" || eff.MimeTypes[".sub"] != "application/x-sub" {
		t.Errorf("MimeTypes = %v, want the entries of both levels", eff.MimeTypes)
	}
	if eff.MimeTypes[".both"] != "application/x-sub-both" {
		t.Errorf(".both = %q, want the deeper file's type", eff.MimeTypes[".both"])
	}
	if !eff.ExpiresActive || eff.ExpiresByType["text/plain"] != "access plus 1 hour" || eff.ExpiresDefault != "access plus 1 day" {
		t.Errorf("expires = active %v by-type %v default %q", eff.ExpiresActive, eff.ExpiresByType, eff.ExpiresDefault)
	}
	if len(eff.DirectoryIndex) != 1 || eff.DirectoryIndex[0] != "home.txt" {
		t.Errorf("DirectoryIndex = %v, want the deeper file's list", eff.DirectoryIndex)
	}
	if eff.ErrorTexts[404] != "sub text" {
		t.Errorf("ErrorTexts[404] = %q", eff.ErrorTexts[404])
	}
	if got := DirSettings([]*RuleSet{root, off}); got.ExpiresActive {
		t.Error("ExpiresActive Off in the sub-directory must switch the inherited On off")
	}
	// Control: the root alone is what the single-file reading always gave.
	if only := DirSettings([]*RuleSet{root}); only.MimeTypes[".sub"] != "" || only.DirectoryIndex[0] != "index.html" {
		t.Errorf("root-only settings leaked: %v %v", only.MimeTypes, only.DirectoryIndex)
	}
	if DirSettings(nil) == nil {
		t.Error("DirSettings(nil) must return an empty RuleSet")
	}
}

// A file that merges blocks keeps the "last ExpiresActive wins" Apache reading.
func TestMergeExpiresActiveLastWins(t *testing.T) {
	a := convertSrc(t, "ExpiresActive On\n")
	b := convertSrc(t, "ExpiresActive Off\n")
	a.Merge(b)
	if a.ExpiresActive {
		t.Error("a later ExpiresActive Off must win over an earlier On")
	}
	c := convertSrc(t, "ExpiresActive Off\n")
	c.Merge(convertSrc(t, "ExpiresActive On\n"))
	if !c.ExpiresActive {
		t.Error("a later ExpiresActive On must win over an earlier Off")
	}
	d := convertSrc(t, "ExpiresActive Off\n")
	d.Merge(convertSrc(t, "Header set X y\n"))
	if d.ExpiresActive {
		t.Error("a block without ExpiresActive must not change it")
	}
}
