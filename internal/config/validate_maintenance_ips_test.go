package config

import (
	"strings"
	"testing"
)

// A maintenance allowed_ips entry that is neither an address nor a CIDR never
// matches, so the operator it was written for gets the maintenance page
// (F15900); validation must refuse it.
func TestValidateDomainRejectsMalformedMaintenanceIPEntry(t *testing.T) {
	cases := []struct {
		entry   string
		wantErr bool
	}{
		{"203.0.113.9", false},
		{"203.0.113.0/24", false},
		{"2001:db8::1", false},
		{"2001:db8::/32", false},
		{"::ffff:203.0.113.9", false},
		{"office", true},
		{"203.0.113.9 ", true},
		{"203.0.113.0/33", true},
		{"", true},
	}
	for _, c := range cases {
		d := &Domain{Host: "example.com", Type: "static", Root: "/tmp",
			Maintenance: MaintenanceConfig{Enabled: true, AllowedIPs: []string{c.entry}}}
		err := ValidateDomain(d)
		if c.wantErr && (err == nil || !strings.Contains(err.Error(), "maintenance.allowed_ips[0]")) {
			t.Errorf("entry %q: err=%v, want a maintenance.allowed_ips[0] error", c.entry, err)
		}
		if !c.wantErr && err != nil {
			t.Errorf("entry %q rejected: %v", c.entry, err)
		}
	}
}
