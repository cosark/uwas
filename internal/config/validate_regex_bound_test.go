package config

import (
	"strings"
	"testing"
)

// F14401: a tenant-settable regex that is far too large to run on every
// request is refused when the domain is validated (the admin API answers 400).
func TestValidateRefusesOversizedLocationAndCacheRuleRegex(t *testing.T) {
	heavy := strings.Repeat("(?:.{100})?", 120) + "x"
	mk := func(loc, rule string) *Domain {
		d := &Domain{Host: "t.example", Type: "static", Root: "/srv/www/t"}
		if loc != "" {
			d.Locations = []LocationConfig{{Match: loc, CacheControl: "no-store"}}
		}
		if rule != "" {
			d.Cache.Rules = []CacheRule{{Match: rule, TTL: 60}}
		}
		return d
	}
	if err := ValidateDomainPartial(mk("~^/api/", `\.(css|js)$`)); err != nil {
		t.Fatalf("control: ordinary patterns rejected: %v", err)
	}
	if err := ValidateDomainPartial(mk("~"+heavy, "")); err == nil || !strings.Contains(err.Error(), "too complex") {
		t.Errorf("heavy location regex: err = %v, want a too-complex refusal", err)
	}
	if err := ValidateDomainPartial(mk("", heavy)); err == nil || !strings.Contains(err.Error(), "too complex") {
		t.Errorf("heavy cache rule regex: err = %v, want a too-complex refusal", err)
	}
}
