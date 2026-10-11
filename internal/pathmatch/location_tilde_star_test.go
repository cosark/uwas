package pathmatch

import "testing"

// "~*" is nginx's case-insensitive regex; it used to fail to compile and so
// never matched, silently disabling the location's basic_auth (F3301).
func TestLocationTildeStarIsCaseInsensitive(t *testing.T) {
	cases := []struct {
		path, pattern string
		want          bool
	}{
		{"/admin/x", "~^/admin", true},
		{"/ADMIN/x", "~^/admin", false},
		{"/admin/x", "~*^/admin", true},
		{"/ADMIN/x", "~*^/admin", true},
		{"/a/B.PHP", `~*\.php$`, true},
		{"/user/x", "~*^/admin", false},
		{"/admin/x", "~*(", false}, // uncompilable never matches
	}
	for _, c := range cases {
		if got := Location(c.path, c.pattern); got != c.want {
			t.Errorf("Location(%q, %q) = %v, want %v", c.path, c.pattern, got, c.want)
		}
	}
	if err := ValidLocation("~*^/admin"); err != nil {
		t.Errorf("ValidLocation(~*^/admin) = %v", err)
	}
	if err := ValidLocation("~*("); err == nil {
		t.Error("ValidLocation(~*() = nil, want error")
	}
	if err := ValidLocation("/prefix("); err != nil {
		t.Errorf("prefix pattern rejected: %v", err)
	}
}
