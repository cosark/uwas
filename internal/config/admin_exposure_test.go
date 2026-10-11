package config

import "testing"

// F16200: the rule the admin API applies at bind time, shared so that a
// reload and a settings update can refuse the same states.
func TestAdminExposureError(t *testing.T) {
	const strong = "S7r0ng-unique-key-9f3c1a77d2"
	cases := []struct {
		name      string
		addr, key string
		multi     bool
		refuse    bool
	}{
		{"public strong key", "0.0.0.0:9443", strong, false, false},
		{"public no key", "0.0.0.0:9443", "", false, true},
		{"public no key but multi-user", "0.0.0.0:9443", "", true, false},
		{"public placeholder", "0.0.0.0:9443", "changeme", false, true},
		{"public placeholder with spaces and case", ":9443", " ChangeMe ", false, true},
		{"public placeholder even with multi-user", "10.0.0.5:9443", "admin", true, true},
		{"loopback no key", "127.0.0.1:9443", "", false, false},
		{"loopback placeholder", "127.0.0.1:9443", "changeme", false, false},
		{"ipv6 loopback placeholder", "[::1]:9443", "changeme", false, false},
		{"localhost placeholder", "localhost:9443", "changeme", false, false},
		{"unparsable address counts as public", "not-an-address", "changeme", false, true},
		{"empty address is the loopback default", "", "changeme", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := AdminExposureError(c.addr, c.key, c.multi)
			if (err != nil) != c.refuse {
				t.Fatalf("AdminExposureError(%q, %q, %v) = %v, refuse=%v", c.addr, c.key, c.multi, err, c.refuse)
			}
		})
	}
}

func TestIsWeakAdminKey(t *testing.T) {
	for _, k := range []string{"changeme", " CHANGEME ", "please-change-this-admin-key", "admin", "password", "secret", "uwas", "test"} {
		if !IsWeakAdminKey(k) {
			t.Errorf("%q should be weak", k)
		}
	}
	for _, k := range []string{"", "S7r0ng-unique-key-9f3c1a77d2", "test-key", "changeme2"} {
		if IsWeakAdminKey(k) {
			t.Errorf("%q should not be weak", k)
		}
	}
}
