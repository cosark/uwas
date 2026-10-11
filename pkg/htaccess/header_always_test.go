package htaccess

import (
	"strings"
	"testing"
)

// F5800: "Header always set ..." (the standard form for security headers) was
// recorded with Action "always", which the server ignores, so the header was
// never sent.
func TestHeaderAlwaysAndOnsuccessKeepTheirAction(t *testing.T) {
	cases := []struct {
		src                 string
		action, name, value string
	}{
		{"Header set X-Frame-Options SAMEORIGIN\n", "set", "X-Frame-Options", "SAMEORIGIN"},
		{"Header always set X-Frame-Options SAMEORIGIN\n", "set", "X-Frame-Options", "SAMEORIGIN"},
		{"Header ALWAYS set Strict-Transport-Security \"max-age=63072000\"\n", "set", "Strict-Transport-Security", "max-age=63072000"},
		{"Header onsuccess set X-Content-Type-Options nosniff\n", "set", "X-Content-Type-Options", "nosniff"},
		{"Header always unset X-Powered-By\n", "unset", "X-Powered-By", ""},
		{"Header always append Vary Accept-Encoding\n", "append", "Vary", "Accept-Encoding"},
	}
	for _, c := range cases {
		ds, err := Parse(strings.NewReader(c.src))
		if err != nil {
			t.Fatal(err)
		}
		hs := Convert(ds).Headers
		if len(hs) != 1 || hs[0].Action != c.action || hs[0].Name != c.name || hs[0].Value != c.value {
			t.Errorf("%q = %+v, want {%s %s %q}", strings.TrimSpace(c.src), hs, c.action, c.name, c.value)
		}
	}
}
