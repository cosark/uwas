package auth

import "testing"

// F13100: an assignment written in one spelling must authorize the same host
// written another way (case, absolute-form dot, Unicode vs punycode), and must
// not authorize a different host.
func TestCanManageDomainComparesCanonicalHostSpellings(t *testing.T) {
	m := &Manager{}
	reseller := &User{Role: RoleReseller, Domains: []string{"Mine.COM", "bücher.example"}}
	for _, c := range []struct {
		domain string
		want   bool
	}{
		{"mine.com", true},
		{"MINE.com.", true},
		{"xn--bcher-kva.example", true},
		{"BÜCHER.example", true},
		{"other.com", false},
		{"sub.mine.com", false},
		{"xn--bcher-kva2.example", false},
		{"", false},
	} {
		if got := m.CanManageDomain(reseller, c.domain); got != c.want {
			t.Errorf("CanManageDomain(%q) = %v, want %v", c.domain, got, c.want)
		}
	}
	punyAssigned := &User{Role: RoleReseller, Domains: []string{"xn--bcher-kva.example"}}
	if !m.CanManageDomain(punyAssigned, "bücher.example") {
		t.Error("punycode assignment must authorize the Unicode spelling")
	}
	if !m.CanManageDomain(&User{Role: RoleAdmin}, "anything.test") {
		t.Error("admin must manage every domain")
	}
}
