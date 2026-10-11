package htaccess

import "testing"

// F8830: "Header ... env=VAR" / "env=!VAR" limits a rule to requests where the
// variable is (not) set. The condition used to be dropped and the header was
// sent to every client, e.g. a CORS header meant for allowed origins only.
func TestHeaderEnvConditionParsedAndDecided(t *testing.T) {
	rs := envRules(t,
		"SetEnvIf Origin \"^https://good\\.example$\" cors_ok\n"+
			"Header set Access-Control-Allow-Origin \"*\" env=cors_ok\n"+
			"Header always set X-Not-Marked yes env=!cors_ok\n"+
			"Header unset X-Powered-By env=cors_ok\n"+
			"Header set X-Plain ok\n")
	if len(rs.Headers) != 4 {
		t.Fatalf("headers = %+v, want 4 rules", rs.Headers)
	}
	wantEnv := []string{"cors_ok", "!cors_ok", "cors_ok", ""}
	for i, h := range rs.Headers {
		if h.Env != wantEnv[i] {
			t.Errorf("rule %d (%s %s) Env = %q, want %q", i, h.Action, h.Name, h.Env, wantEnv[i])
		}
	}
	if rs.Headers[0].Value != "*" || rs.Headers[1].Value != "yes" {
		t.Errorf("values changed: %+v", rs.Headers[:2])
	}

	attrs := func(origin string) *RequestAttrs {
		a := envAttrs("Mozilla")
		if origin != "" {
			a.Header.Set("Origin", origin)
		}
		return a
	}
	for _, c := range []struct {
		origin string
		want   [4]bool
	}{
		{"https://good.example", [4]bool{true, false, true, true}},
		{"https://evil.example", [4]bool{false, true, false, true}},
		{"", [4]bool{false, true, false, true}},
	} {
		for i, h := range rs.Headers {
			if got := h.AppliesTo(rs, attrs(c.origin)); got != c.want[i] {
				t.Errorf("origin %q rule %d (%s): applies = %v, want %v", c.origin, i, h.Name, got, c.want[i])
			}
		}
	}
	// Without request attributes a conditional rule cannot be decided and is
	// skipped; an unconditional one still applies.
	if rs.Headers[0].AppliesTo(rs, nil) || !rs.Headers[3].AppliesTo(rs, nil) {
		t.Error("nil attrs: conditional rule must be skipped, plain rule applied")
	}
}

// The built-in HTTPS variable, as mod_ssl sets it, is what the common
// "Header always set Strict-Transport-Security ... env=HTTPS" line relies on.
func TestHeaderEnvBuiltinHTTPS(t *testing.T) {
	rs := envRules(t, "Header always set Strict-Transport-Security \"max-age=63072000\" env=HTTPS\n")
	if len(rs.Headers) != 1 || rs.Headers[0].Env != "HTTPS" {
		t.Fatalf("headers = %+v", rs.Headers)
	}
	plain, tls := envAttrs("x"), envAttrs("x")
	tls.HTTPS = true
	if rs.Headers[0].AppliesTo(rs, plain) {
		t.Error("HSTS applied over plain HTTP")
	}
	if !rs.Headers[0].AppliesTo(rs, tls) {
		t.Error("HSTS not applied over TLS")
	}
}

// A variable an unevaluable SetEnvIf (PCRE-only regex) would define is
// undecidable; the rule is skipped, never applied to everyone.
func TestHeaderEnvUndecidableIsSkipped(t *testing.T) {
	rs := envRules(t,
		"SetEnvIf User-Agent \"(?<!x)bot\" bad\n"+
			"Header set X-Bad yes env=bad\n"+
			"Header set X-NotBad yes env=!bad\n")
	for _, h := range rs.Headers {
		if h.AppliesTo(rs, envAttrs("Mozilla")) {
			t.Errorf("%s applied although its condition cannot be decided", h.Name)
		}
	}
}
