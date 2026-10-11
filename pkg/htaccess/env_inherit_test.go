package htaccess

import (
	"net"
	"testing"
)

// F7000: a parent directory's SetEnvIf must govern the "Deny from env=" of a
// subdirectory's .htaccess once the parent's rules are inherited.
func TestEnvInheritedFromParentDirectory(t *testing.T) {
	ip := net.ParseIP("198.51.100.7")
	parent := envRules(t, "SetEnvIf User-Agent \"BadBot\" bad_bot\n")
	child := envRules(t, "Order Allow,Deny\nAllow from all\nDeny from env=bad_bot\n")

	// Without inheritance the child cannot see the variable (the control the
	// server relied on before F7000).
	if got := child.AccessForRequest(ip, "GET", envAttrs("BadBot/1")); got != AccessGranted {
		t.Fatalf("no inheritance: got %v, want granted", got)
	}

	for _, c := range []struct {
		ua   string
		want AccessDecision
	}{
		{"BadBot/1", AccessDenied},
		{"Mozilla/5.0", AccessGranted},
	} {
		attrs := envAttrs(c.ua)
		attrs.Inherit(parent)
		if got := child.AccessForRequest(ip, "GET", attrs); got != c.want {
			t.Errorf("UA %q: got %v, want %v", c.ua, got, c.want)
		}
	}

	// A deeper unset overrides what the parent set, like Apache's sequential merge.
	unset := envRules(t, "UnsetEnv bad_bot\nOrder Allow,Deny\nAllow from all\nDeny from env=bad_bot\n")
	attrs := envAttrs("BadBot/1")
	attrs.Inherit(parent)
	if got := unset.AccessForRequest(ip, "GET", attrs); got != AccessGranted {
		t.Errorf("UnsetEnv in the child: got %v, want granted", got)
	}

	// Inherit on nil receivers/rules is a no-op.
	var nilAttrs *RequestAttrs
	nilAttrs.Inherit(parent)
	envAttrs("x").Inherit(nil)
}
