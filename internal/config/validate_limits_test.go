package config

import (
	"strings"
	"testing"
)

// F7800/F7801: a negative resource or bandwidth limit, or a bandwidth action the
// manager does not enforce, used to be accepted and left the domain unlimited.
func TestValidateDomainRejectsLimitsThatDisableThemselves(t *testing.T) {
	mk := func(mut func(*Domain)) *Domain {
		d := &Domain{Host: "example.com", Type: "static", Root: "/tmp"}
		mut(d)
		return d
	}
	ok := mk(func(d *Domain) {
		d.Resources = ResourceLimits{CPUPercent: 50, MemoryMB: 256, PIDMax: 100}
		d.Bandwidth = BandwidthConfig{Enabled: true, MonthlyLimit: 1 << 20, DailyLimit: 1 << 10, Action: "block"}
	})
	if err := ValidateDomain(ok); err != nil {
		t.Fatalf("valid limits rejected: %v", err)
	}
	for _, action := range []string{"", "throttle", "alert"} {
		d := mk(func(d *Domain) { d.Bandwidth = BandwidthConfig{Enabled: true, Action: action} })
		if err := ValidateDomain(d); err != nil {
			t.Errorf("bandwidth.action %q rejected: %v", action, err)
		}
	}

	cases := map[string]struct {
		mut  func(*Domain)
		want string
	}{
		"cpu":      {func(d *Domain) { d.Resources.CPUPercent = -50 }, "resources.cpu_percent"},
		"memory":   {func(d *Domain) { d.Resources.MemoryMB = -1 }, "resources.memory_mb"},
		"pid":      {func(d *Domain) { d.Resources.PIDMax = -1 }, "resources.pid_max"},
		"monthly":  {func(d *Domain) { d.Bandwidth.MonthlyLimit = -1 }, "bandwidth.monthly_limit"},
		"daily":    {func(d *Domain) { d.Bandwidth.DailyLimit = -1 }, "bandwidth.daily_limit"},
		"misspelt": {func(d *Domain) { d.Bandwidth = BandwidthConfig{Enabled: true, MonthlyLimit: 1, Action: "Block"} }, "bandwidth.action"},
	}
	for name, c := range cases {
		err := ValidateDomain(mk(c.mut))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err=%v, want one naming %s", name, err, c.want)
		}
	}
}
