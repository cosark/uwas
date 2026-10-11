package config

import (
	"strings"
	"testing"
)

// A "~" location whose regex does not compile never matches, so its
// basic_auth or rate_limit silently never applied (F3300).
func TestValidateDomainRejectsUncompilableLocationRegex(t *testing.T) {
	cases := []struct {
		match   string
		wantErr bool
	}{
		{"/api/", false},
		{"/a(b", false}, // a prefix, not a regex
		{"~^/admin(/|$)", false},
		{"~*^/admin", false}, // nginx case-insensitive form (F3301)
		{"", false},
		{"~^/admin(", true},
		{"~[a-", true},
		{"~*(", true},
	}
	for _, c := range cases {
		d := &Domain{Host: "example.com", Type: "static", Root: "/tmp",
			Locations: []LocationConfig{{Match: c.match}}}
		err := ValidateDomain(d)
		if (err != nil) != c.wantErr {
			t.Errorf("match %q: err=%v, wantErr=%v", c.match, err, c.wantErr)
		}
		if err != nil && !strings.Contains(err.Error(), "locations[0].match") {
			t.Errorf("match %q: error %q does not name the field", c.match, err)
		}
	}
}
