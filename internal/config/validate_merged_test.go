package config

import "testing"

// F16800: an update judges the domain it is about to store, after the patch is
// merged. ValidateDomainPartial skips the cross-field rules on purpose (it was
// written for a patch alone), so using it on the merged domain accepted a
// write the next start refuses to load, and an internal redirect target Add
// refuses.
func TestValidateMergedDomainJudgesTheWholeDomain(t *testing.T) {
	static := Domain{Host: "a.example", Type: "static", Root: "/var/www/a", SSL: SSLConfig{Mode: "off"}}
	redirect := Domain{Host: "r.example", Type: "redirect", Redirect: RedirectConfig{Target: "https://ok.example/", Status: 301}, SSL: SSLConfig{Mode: "off"}}
	legacy := Domain{Host: "l.example", Type: "redirect", Redirect: RedirectConfig{Target: "http://10.1.2.3/portal", Status: 302}, SSL: SSLConfig{Mode: "off"}}

	for _, tc := range []struct {
		name    string
		prev    Domain
		patch   Domain
		fields  DomainPatchFields
		wantErr bool
	}{
		{"type proxy without upstreams", static, Domain{Type: "proxy"}, DomainPatchFields{}, true},
		{"type redirect without a target", static, Domain{Type: "redirect"}, DomainPatchFields{}, true},
		{"redirect target to the metadata endpoint", redirect, Domain{Redirect: RedirectConfig{Target: "http://169.254.169.254/latest/"}}, DomainPatchFields{}, true},
		{"static -> redirect to an internal host", static, Domain{Type: "redirect", Redirect: RedirectConfig{Target: "http://127.0.0.1:9443/"}}, DomainPatchFields{}, true},
		{"client_auth with no CA anywhere", static, Domain{SSL: SSLConfig{Mode: "off", ClientAuth: "require"}}, DomainPatchFields{HasSSL: true}, true},
		{"basic_auth enabled without users", static, Domain{BasicAuth: BasicAuthConfig{Enabled: true}}, DomainPatchFields{HasBasicAuth: true}, true},

		// controls
		{"unrelated edit", static, Domain{Cache: DomainCache{Enabled: true, TTL: 60}}, DomainPatchFields{HasCache: true}, false},
		{"proxy with an upstream", static, Domain{Type: "proxy", Proxy: ProxyConfig{Upstreams: []Upstream{{Address: "http://127.0.0.1:9000", Weight: 1}}}}, DomainPatchFields{}, false},
		{"redirect to a public target", static, Domain{Type: "redirect", Redirect: RedirectConfig{Target: "https://example.org/"}}, DomainPatchFields{}, false},
		{"unrelated edit of a legacy internal redirect", legacy, Domain{Cache: DomainCache{Enabled: true, TTL: 30}}, DomainPatchFields{HasCache: true}, false},
		{"client_auth next to a stored CA", Domain{Host: "c.example", Type: "static", Root: "/var/www/c", SSL: SSLConfig{Mode: "off", ClientCA: "/etc/ssl/ca.pem"}}, Domain{SSL: SSLConfig{Mode: "off", ClientAuth: "require"}}, DomainPatchFields{HasSSL: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prev := tc.prev
			merged := MergeDomain(prev, tc.patch, tc.fields, false)
			err := ValidateMergedDomain(&merged, &prev)
			if tc.wantErr && err == nil {
				t.Errorf("a write the next start refuses (or Add refuses) was accepted: %+v", merged)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("a valid update was refused: %v", err)
			}
		})
	}

	// Changing a legacy internal target is judged: only an UNCHANGED target is
	// left alone.
	moved := MergeDomain(legacy, Domain{Redirect: RedirectConfig{Target: "http://169.254.169.254/"}}, DomainPatchFields{}, false)
	if err := ValidateMergedDomain(&moved, &legacy); err == nil {
		t.Error("moving a redirect to the metadata endpoint was accepted")
	}
	if err := ValidateMergedDomain(nil, nil); err == nil {
		t.Error("a nil domain was accepted")
	}
}
