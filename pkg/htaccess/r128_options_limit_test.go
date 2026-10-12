package htaccess

import (
	"strings"
	"testing"
)

func convertText(t *testing.T, src string) *RuleSet {
	t.Helper()
	d, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	return Convert(d)
}

func TestLimitRequestBodyValueTable(t *testing.T) {
	cases := []struct {
		in   string
		want int64 // -1 = not recorded
	}{
		{"LimitRequestBody 1024", 1024},
		{"LimitRequestBody 0", 0},
		{`LimitRequestBody "2048"`, 2048},
		{"limitrequestbody 10", 10},
		{"LimitRequestBody -1", -1},
		{"LimitRequestBody 0x10", -1},
		{"LimitRequestBody 10k", -1},
		{"LimitRequestBody 1.5", -1},
		{"LimitRequestBody 99999999999999999999", -1},
		{"LimitRequestBody abc", -1},
		{"LimitRequestBody", -1},
	}
	for _, c := range cases {
		rs := convertText(t, c.in+"\n")
		if c.want < 0 {
			if rs.LimitRequestBody != nil {
				t.Errorf("%q recorded %d, want ignored", c.in, *rs.LimitRequestBody)
			}
			continue
		}
		if rs.LimitRequestBody == nil || *rs.LimitRequestBody != c.want {
			t.Errorf("%q = %v, want %d", c.in, rs.LimitRequestBody, c.want)
		}
	}
	// Deepest wins; an unparsable deeper value does not lift the parent's cap.
	a, b, c := convertText(t, "LimitRequestBody 100\n"), convertText(t, "LimitRequestBody 0\n"), convertText(t, "LimitRequestBody abc\n")
	if got := LimitRequestBodyFor([]*RuleSet{a, nil, b}); got != 0 {
		t.Errorf("deeper 0 = %d", got)
	}
	if got := LimitRequestBodyFor([]*RuleSet{a, c}); got != 100 {
		t.Errorf("garbage child lifted parent cap: %d", got)
	}
}

func TestOptionsFollowSymlinksTable(t *testing.T) {
	cases := []struct {
		in     string
		set    bool
		follow bool
	}{
		{"Options -FollowSymLinks", true, false},
		{"Options +FollowSymLinks", true, true},
		{"Options FollowSymLinks", true, true},
		{"Options All", true, true},
		{"Options None", true, false},
		{"Options Indexes", true, false},
		{"Options -FollowSymLinks +SymLinksIfOwnerMatch", true, false},
		{"Options FollowSymLinks -FollowSymLinks", true, false},
		{"options -followsymlinks", true, false},
		{`Options "-FollowSymLinks"`, true, false},
		{"Options +Indexes", false, false},
		{"Options -Indexes", false, false},
	}
	for _, c := range cases {
		rs := convertText(t, c.in+"\n")
		if (rs.FollowSymlinks != nil) != c.set {
			t.Errorf("%q set=%v, want %v", c.in, rs.FollowSymlinks != nil, c.set)
			continue
		}
		if c.set && *rs.FollowSymlinks != c.follow {
			t.Errorf("%q follow=%v, want %v", c.in, *rs.FollowSymlinks, c.follow)
		}
	}
}

func TestFollowSymlinksForChain(t *testing.T) {
	off := convertText(t, "Options -FollowSymLinks\n")
	on := convertText(t, "Options +FollowSymLinks\n")
	none := convertText(t, "RewriteEngine On\n")
	if f, l := FollowSymlinksFor(nil); !f || l != -1 {
		t.Errorf("empty chain = %v,%d", f, l)
	}
	if f, l := FollowSymlinksFor([]*RuleSet{off, none}); f || l != 0 {
		t.Errorf("parent off, silent child = %v,%d", f, l)
	}
	if f, l := FollowSymlinksFor([]*RuleSet{off, nil, on}); !f || l != 2 {
		t.Errorf("child +FollowSymLinks must lift parent = %v,%d", f, l)
	}
}
