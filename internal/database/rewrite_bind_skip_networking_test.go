package database

import (
	"strings"
	"testing"
)

// MySQL/MariaDB treat '-' and '_' in option names as equal; a config using
// skip_networking must be disabled the same way skip-networking is, or remote
// access is reported as configured while TCP stays off (F22100).
func TestRewriteBindAddressDisablesSkipNetworkingSpellings(t *testing.T) {
	active := func(out, key string) bool {
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(l)), key) {
				return true
			}
		}
		return false
	}
	cases := []struct{ name, in, key string }{
		{"dashed", "[mysqld]\nskip-networking\n", "skip-networking"},
		{"underscore", "[mysqld]\nskip_networking\n", "skip_networking"},
		{"underscore with value", "[mysqld]\nskip_networking = 1\nbind_address = 127.0.0.1\n", "skip_networking"},
		{"mixed case", "[mysqld]\nSkip_Networking\n", "skip_networking"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rewriteBindAddress(tc.in)
			if active(got, tc.key) {
				t.Fatalf("%s still active:\n%s", tc.key, got)
			}
			if !strings.Contains(got, "bind-address = 0.0.0.0") {
				t.Fatalf("bind-address not opened:\n%s", got)
			}
			if !strings.Contains(got, "# ") {
				t.Fatalf("original option should be kept as a comment:\n%s", got)
			}
		})
	}
	t.Run("outside mysqld untouched", func(t *testing.T) {
		got := rewriteBindAddress("[client]\nskip_networking\n[mysqld]\nport = 3306\n")
		if !strings.Contains(got, "[client]\nskip_networking\n") {
			t.Fatalf("client section changed:\n%s", got)
		}
	})
	t.Run("repeated call stable", func(t *testing.T) {
		once := rewriteBindAddress("[mysqld]\nskip_networking\n")
		if twice := rewriteBindAddress(once); twice != once {
			t.Fatalf("not idempotent:\n%s\n---\n%s", once, twice)
		}
	})
}
