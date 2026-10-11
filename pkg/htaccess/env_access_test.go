package htaccess

import (
	"net"
	"net/http"
	"strings"
	"testing"
)

func envRules(t *testing.T, src string) *RuleSet {
	t.Helper()
	ds, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	return Convert(ds)
}

func envAttrs(ua string) *RequestAttrs {
	h := http.Header{}
	if ua != "" {
		h.Set("User-Agent", ua)
	}
	return &RequestAttrs{RemoteAddr: "198.51.100.7", Method: "GET", URI: "/x", Proto: "HTTP/1.1", Host: "a.test", Header: h}
}

// F6700: SetEnvIf/BrowserMatch/SetEnv define variables that "Deny from env=",
// "Allow from env=" and "Require [not] env" read; they used to fail closed for
// every client, so a good User-Agent was refused too.
func TestEnvConditionsDecidedFromRequest(t *testing.T) {
	ip := net.ParseIP("198.51.100.7")
	cases := []struct {
		name, src, ua string
		want          AccessDecision
	}{
		{"deny from env, good UA", "SetEnvIf User-Agent \"BadBot\" bad\nOrder Allow,Deny\nAllow from all\nDeny from env=bad\n", "Mozilla", AccessGranted},
		{"deny from env, bad UA", "SetEnvIf User-Agent \"BadBot\" bad\nOrder Allow,Deny\nAllow from all\nDeny from env=bad\n", "BadBot/1", AccessDenied},
		{"deny from env=!x", "BrowserMatch \"Good\" ok\nOrder Allow,Deny\nAllow from all\nDeny from env=!ok\n", "Mozilla", AccessDenied},
		{"deny from env=!x, matching", "BrowserMatch \"Good\" ok\nOrder Allow,Deny\nAllow from all\nDeny from env=!ok\n", "GoodUA", AccessGranted},
		{"allow from env", "BrowserMatchNoCase \"office\" in\nOrder Deny,Allow\nDeny from all\nAllow from env=in\n", "OFFICE-client", AccessGranted},
		{"allow from env, other", "BrowserMatchNoCase \"office\" in\nOrder Deny,Allow\nDeny from all\nAllow from env=in\n", "Mozilla", AccessDenied},
		{"require env", "SetEnvIf Remote_Addr \"^198\\.51\\.\" office\nRequire env office\n", "x", AccessGranted},
		{"require env, no match", "SetEnvIf Remote_Addr \"^10\\.\" office\nRequire env office\n", "x", AccessDenied},
		{"require not env", "BrowserMatch Evil evil\n<RequireAll>\nRequire all granted\nRequire not env evil\n</RequireAll>\n", "EvilBot", AccessDenied},
		{"require not env, good", "BrowserMatch Evil evil\n<RequireAll>\nRequire all granted\nRequire not env evil\n</RequireAll>\n", "Mozilla", AccessGranted},
		{"setenv always defined", "SetEnv flag 1\nRequire env flag\n", "x", AccessGranted},
		{"unsetenv after set", "SetEnv flag 1\nUnsetEnv flag\nRequire env flag\n", "x", AccessDenied},
		{"negated SetEnvIf clears", "SetEnv flag 1\nSetEnvIf User-Agent Mozilla !flag\nRequire env flag\n", "Mozilla", AccessDenied},
		{"inside IfModule", "<IfModule mod_setenvif.c>\nSetEnvIf User-Agent \"BadBot\" bad\n</IfModule>\nOrder Allow,Deny\nAllow from all\nDeny from env=bad\n", "Mozilla", AccessGranted},
		{"absent header does not match", "SetEnvIf X-Token \".*\" has_token\nRequire env has_token\n", "Mozilla", AccessDenied},
		// PCRE-only regex cannot be evaluated: fail closed, never grant.
		{"uncompilable regex fails closed", "SetEnvIf User-Agent \"(?<!x)bot\" bad\nOrder Allow,Deny\nAllow from all\nDeny from env=bad\n", "Mozilla", AccessDenied},
		{"uncompilable regex never grants", "SetEnvIf User-Agent \"(?<!x)bot\" office\nRequire env office\n", "bot", AccessDenied},
	}
	for _, c := range cases {
		if got := envRules(t, c.src).AccessForRequest(ip, "GET", envAttrs(c.ua)); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// Without request attributes an env condition still fails closed (the
// method-only entry points keep their behaviour).
func TestEnvConditionsFailClosedWithoutAttrs(t *testing.T) {
	ip := net.ParseIP("198.51.100.7")
	deny := envRules(t, "SetEnvIf User-Agent \"BadBot\" bad\nOrder Allow,Deny\nAllow from all\nDeny from env=bad\n")
	if got := deny.AccessForMethod(ip, "GET"); got != AccessDenied {
		t.Errorf("Deny from env= without attrs: %v, want denied", got)
	}
	req := envRules(t, "SetEnv flag 1\nRequire env flag\n")
	if got := req.AccessForMethod(ip, "GET"); got != AccessDenied {
		t.Errorf("Require env without attrs: %v, want denied", got)
	}
}

// An env condition inside <FilesMatch> is decided with the request too.
func TestFilesMatchEnvConditionDecided(t *testing.T) {
	ip := net.ParseIP("198.51.100.7")
	rs := envRules(t, "SetEnvIf User-Agent \"BadBot\" bad\n<FilesMatch \"\\.sql$\">\nOrder Allow,Deny\nAllow from all\nDeny from env=bad\n</FilesMatch>\n")
	if FilesMatchDeniesForRequest(rs, "dump.sql", ip, "GET", envAttrs("Mozilla")) {
		t.Error("good UA denied for dump.sql")
	}
	if !FilesMatchDeniesForRequest(rs, "dump.sql", ip, "GET", envAttrs("BadBot")) {
		t.Error("bad UA allowed for dump.sql")
	}
	if FilesMatchDeniesForRequest(rs, "page.html", ip, "GET", envAttrs("BadBot")) {
		t.Error("control page.html denied")
	}
	if !FilesMatchDeniesForMethod(rs, "dump.sql", ip, "GET") {
		t.Error("method-only entry point must keep failing closed")
	}
}
