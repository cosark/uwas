package cli

import (
	"strings"
	"testing"
)

// F22000: Apache accepts quoted ProxyPass and ServerAlias arguments; the
// quotes must not leak into the migrated paths, upstreams or aliases.
func TestApacheMigrationQuotedProxyPassAndAlias(t *testing.T) {
	out := convertApacheForTest(t, "ServerAlias \"www.a.com\" 'm.a.com'\nProxyPass \"/\" \"http://127.0.0.1:3000/\"\n")
	for _, want := range []string{"type: proxy", "- address: http://127.0.0.1:3000/", "- www.a.com", "- m.a.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, `\"`) {
		t.Errorf("quote leaked into output:\n%s", out)
	}
}

func TestApacheMigrationQuotedLocationProxyPass(t *testing.T) {
	out := convertApacheForTest(t, "ProxyPass \"/api\" \"http://127.0.0.1:4000/\"\nProxyPass \"/static\" !\n")
	if !strings.Contains(out, "match: /api") || !strings.Contains(out, "proxy_pass: http://127.0.0.1:4000") {
		t.Errorf("quoted location not migrated:\n%s", out)
	}
	if strings.Contains(out, "/static") || strings.Contains(out, `\"`) {
		t.Errorf("excluded path or quote leaked:\n%s", out)
	}
}

func TestSplitApacheArgs(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"ProxyPass / http://x/", []string{"ProxyPass", "/", "http://x/"}},
		{`ProxyPass "/a b" 'http://x/'`, []string{"ProxyPass", "/a b", "http://x/"}},
		{`ServerAlias "a\"b" c`, []string{"ServerAlias", `a"b`, "c"}},
		{"ServerAlias", []string{"ServerAlias"}},
		{"ServerAlias\ta  b", []string{"ServerAlias", "a", "b"}},
		{`X ""`, []string{"X", ""}},
	}
	for _, tc := range cases {
		got := splitApacheArgs(tc.in)
		if strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") || len(got) != len(tc.want) {
			t.Errorf("splitApacheArgs(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
