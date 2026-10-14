package config

import (
	"math"
	"strings"
	"testing"
)

// php.max_upload must stay in the range its consumers can use: they add 1MB of
// headroom to it, so a value within 1MB of MaxInt64 wraps to a negative limit
// (every chunked upload gets 413), and a negative one was silently read as
// "unset" (F19500).
func TestValidatePHPMaxUploadRange(t *testing.T) {
	mk := func(v ByteSize) Domain {
		return Domain{Host: "a.example.com", Type: "php", Root: "/var/www/a", SSL: SSLConfig{Mode: "off"}, PHP: PHPConfig{MaxUpload: v}}
	}
	const top = ByteSize(math.MaxInt64) - MB
	for _, tc := range []struct {
		name string
		v    ByteSize
		ok   bool
	}{
		{"unset", 0, true},
		{"typical", 64 * MB, true},
		{"large", 8 * GB, true},
		{"largest usable", top, true},
		{"one past largest usable", top + 1, false},
		{"max int64", ByteSize(math.MaxInt64), false},
		{"negative", -1, false},
		{"min int64", ByteSize(math.MinInt64), false},
	} {
		d := mk(tc.v)
		for _, run := range []struct {
			name string
			fn   func() error
		}{
			{"strict", func() error { return ValidateDomain(&d) }},
			{"partial", func() error { return ValidateDomainPartial(&d) }},
			{"loader", func() error {
				cfg := &Config{Domains: []Domain{d}}
				return ValidateWithDefaults(cfg)
			}},
		} {
			err := run.fn()
			if tc.ok && err != nil {
				t.Errorf("%s/%s: max_upload %d rejected: %v", tc.name, run.name, tc.v, err)
			}
			if !tc.ok && (err == nil || !strings.Contains(err.Error(), "php.max_upload")) {
				t.Errorf("%s/%s: max_upload %d accepted or wrong error: %v", tc.name, run.name, tc.v, err)
			}
		}
	}
}
