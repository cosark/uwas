package htaccess

import (
	"net"
	"strings"
	"testing"
)

func requireAccess(t *testing.T, src, ip string) AccessDecision {
	t.Helper()
	ds, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	return Convert(ds).AccessForMethod(net.ParseIP(ip), "GET")
}

// F12400: <RequireNone> is satisfied only when none of its conditions match.
// A condition this server cannot evaluate (expr, host, method, ...) might
// match the client, so it must not count as "does not match": the container,
// and the <RequireAll> around it, must not grant.
func TestRequireNoneWithUnevaluableConditionFailsClosed(t *testing.T) {
	wrap := func(inner string) string {
		return "<RequireAll>\nRequire all granted\n<RequireNone>\n" + inner + "\n</RequireNone>\n</RequireAll>\n"
	}
	const client = "198.51.100.7"
	cases := []struct {
		name string
		src  string
		want AccessDecision
	}{
		// Controls: evaluable conditions behave as Apache does.
		{"control matching ip denies", wrap("Require ip 198.51.100.0/24"), AccessDenied},
		{"control other ip grants", wrap("Require ip 203.0.113.0/24"), AccessGranted},
		// The defect.
		{"expr cannot be evaluated", wrap(`Require expr "%{HTTP_USER_AGENT} =~ /bad/"`), AccessDenied},
		{"host cannot be evaluated", wrap("Require host evil.example"), AccessDenied},
		{"method cannot be evaluated", wrap("Require method POST"), AccessDenied},
		{"unknown beside non-matching ip", wrap("Require ip 203.0.113.0/24\nRequire expr \"1\""), AccessDenied},
		// A match settles the container whatever else is unknown.
		{"matching ip beside unknown denies", wrap("Require ip 198.51.100.0/24\nRequire host evil.example"), AccessDenied},
		// Nested containers: unknown inside a RequireAny that nothing grants.
		{"nested any unknown", wrap("<RequireAny>\nRequire ip 203.0.113.0/24\nRequire host evil.example\n</RequireAny>"), AccessDenied},
		// A nested RequireAll with a decidedly failing condition settles false.
		{"nested all settled false grants", wrap("<RequireAll>\nRequire ip 203.0.113.0/24\nRequire host evil.example\n</RequireAll>"), AccessGranted},
		// Unevaluable conditions outside RequireNone stay fail-closed.
		{"top level expr", "Require expr \"1\"\n", AccessDenied},
		{"all granted with method", "<RequireAll>\nRequire all granted\nRequire method GET\n</RequireAll>\n", AccessDenied},
	}
	for _, c := range cases {
		if got := requireAccess(t, c.src, client); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
