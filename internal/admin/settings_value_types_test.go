package admin

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
)

// F14000-F14003: PUT /api/v1/settings parsed durations, sizes, integers and
// booleans with helpers that turn anything they do not understand into zero or
// false and then answer 200 "saved". "1d" or a bare 45 became a 0s timeout,
// a JSON number 268435456 (printed as 2.68435456e+08) became a 0-byte cache,
// "1h" for a TTL became 1 second and "True" switched a protection off. The
// loader reads a bare number as seconds (durations) or bytes (sizes), so the
// API must read the same, and refuse what it cannot read instead of storing
// something else.

func putSettingsStatus(s *Server, payload string) (int, string) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/v1/settings", strings.NewReader(payload))
	req.RemoteAddr = "10.0.0.1:1234"
	s.handleSettingsPut(rec, withAdminContext(req))
	return rec.Code, rec.Body.String()
}

func TestSettingsPutDurationsReadLikeTheLoader(t *testing.T) {
	type row struct {
		name    string
		payload string
		want    time.Duration
		reject  bool
	}
	for _, tc := range []row{
		{"duration string (control)", `{"global.timeouts.read": "45s"}`, 45 * time.Second, false},
		{"compound duration", `{"global.timeouts.read": "1m30s"}`, 90 * time.Second, false},
		{"bare JSON number is seconds", `{"global.timeouts.read": 45}`, 45 * time.Second, false},
		{"bare numeric string is seconds", `{"global.timeouts.read": "45"}`, 45 * time.Second, false},
		{"empty clears to the default", `{"global.timeouts.read": ""}`, 0, false},
		{"unit the parser does not know", `{"global.timeouts.read": "1d"}`, 0, true},
		{"words", `{"global.timeouts.read": "45 seconds"}`, 0, true},
		{"junk", `{"global.timeouts.read": "banana"}`, 0, true},
		{"boolean", `{"global.timeouts.read": true}`, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := settingsTestServer(t)
			s.config.Global.Timeouts.Read = config.Duration{Duration: 7 * time.Second}
			code, body := putSettingsStatus(s, tc.payload)
			got := s.config.Global.Timeouts.Read.Duration
			if tc.reject {
				if code != 400 || !strings.Contains(body, "global.timeouts.read") {
					t.Errorf("status = %d body %q, want 400 naming the key", code, body)
				}
				if got != 7*time.Second {
					t.Errorf("a rejected value changed the setting to %v", got)
				}
				return
			}
			if code != 200 || got != tc.want {
				t.Errorf("status = %d, read timeout = %v, want 200 and %v", code, got, tc.want)
			}
		})
	}

	// The other duration settings share the parser.
	s := settingsTestServer(t)
	if code, body := putSettingsStatus(s, `{"global.rate_limit.window": 60, "global.watchdog.interval": "30", "global.autoblock.block_duration": "15m"}`); code != 200 {
		t.Fatalf("status = %d, %s", code, body)
	}
	g := s.config.Global
	if g.RateLimit.Window.Duration != time.Minute || g.Watchdog.Interval.Duration != 30*time.Second ||
		g.AutoBlock.BlockDuration.Duration != 15*time.Minute {
		t.Errorf("window=%v interval=%v block=%v", g.RateLimit.Window.Duration, g.Watchdog.Interval.Duration, g.AutoBlock.BlockDuration.Duration)
	}
	if code, _ := putSettingsStatus(s, `{"global.autoblock.window": "banana"}`); code != 400 {
		t.Errorf("autoblock.window junk: status = %d, want 400", code)
	}
}

func TestSettingsPutByteSizesReadLikeTheLoader(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		want    config.ByteSize
		reject  bool
	}{
		{"size string (control)", `{"global.cache.memory_limit": "256MB"}`, 256 * config.MB, false},
		{"space before the unit", `{"global.cache.memory_limit": "256 MB"}`, 256 * config.MB, false},
		{"fractional gigabytes", `{"global.cache.memory_limit": "1.5GB"}`, 3 * config.GB / 2, false},
		{"bare JSON number is bytes", `{"global.cache.memory_limit": 268435456}`, 256 * config.MB, false},
		{"one megabyte as a number", `{"global.cache.memory_limit": 1048576}`, config.MB, false},
		{"bare numeric string is bytes", `{"global.cache.memory_limit": "268435456"}`, 256 * config.MB, false},
		{"empty clears to the default", `{"global.cache.memory_limit": ""}`, 0, false},
		{"binary unit the parser does not know", `{"global.cache.memory_limit": "1GiB"}`, 0, true},
		{"junk", `{"global.cache.memory_limit": "abc"}`, 0, true},
		{"fractional bytes", `{"global.cache.memory_limit": 1.5}`, 0, true},
		{"negative", `{"global.cache.memory_limit": -5}`, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := settingsTestServer(t)
			s.config.Global.Cache.MemoryLimit = 64 * config.MB
			code, body := putSettingsStatus(s, tc.payload)
			got := s.config.Global.Cache.MemoryLimit
			if tc.reject {
				if code != 400 || !strings.Contains(body, "global.cache.memory_limit") {
					t.Errorf("status = %d body %q, want 400 naming the key", code, body)
				}
				if got != 64*config.MB {
					t.Errorf("a rejected value changed the setting to %d", got)
				}
				return
			}
			if code != 200 || got != tc.want {
				t.Errorf("status = %d, memory limit = %d, want 200 and %d", code, got, tc.want)
			}
		})
	}
}

func TestSettingsPutIntegersAreNotTruncatedOrZeroed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		want    int
		reject  bool
	}{
		{"number (control)", `{"global.cache.default_ttl": 3600}`, 3600, false},
		{"numeric string (control)", `{"global.cache.default_ttl": "3600"}`, 3600, false},
		{"empty clears", `{"global.cache.default_ttl": ""}`, 0, false},
		{"a duration where seconds belong", `{"global.cache.default_ttl": "1h"}`, 0, true},
		{"fraction", `{"global.cache.default_ttl": 1.5}`, 0, true},
		{"junk", `{"global.cache.default_ttl": "abc"}`, 0, true},
		{"boolean", `{"global.cache.default_ttl": true}`, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := settingsTestServer(t)
			s.config.Global.Cache.DefaultTTL = 77
			code, body := putSettingsStatus(s, tc.payload)
			got := s.config.Global.Cache.DefaultTTL
			if tc.reject {
				if code != 400 || !strings.Contains(body, "global.cache.default_ttl") {
					t.Errorf("status = %d body %q, want 400 naming the key", code, body)
				}
				if got != 77 {
					t.Errorf("a rejected value changed the setting to %d", got)
				}
				return
			}
			if code != 200 || got != tc.want {
				t.Errorf("status = %d, default_ttl = %d, want 200 and %d", code, got, tc.want)
			}
		})
	}
}

func TestSettingsPutBooleansAreNotSilentlyFalse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		want    bool
		reject  bool
	}{
		{"true (control)", `{"global.autoblock.enabled": true}`, true, false},
		{"string true", `{"global.autoblock.enabled": "true"}`, true, false},
		{"capitalised", `{"global.autoblock.enabled": "True"}`, true, false},
		{"false", `{"global.autoblock.enabled": false}`, false, false},
		{"string false", `{"global.autoblock.enabled": "FALSE"}`, false, false},
		{"yes", `{"global.autoblock.enabled": "yes"}`, false, true},
		{"one", `{"global.autoblock.enabled": 1}`, false, true},
		{"junk", `{"global.autoblock.enabled": "maybe"}`, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := settingsTestServer(t)
			s.config.Global.AutoBlock.Enabled = !tc.want
			code, body := putSettingsStatus(s, tc.payload)
			got := s.config.Global.AutoBlock.Enabled
			if tc.reject {
				if code != 400 || !strings.Contains(body, "global.autoblock.enabled") {
					t.Errorf("status = %d body %q, want 400 naming the key", code, body)
				}
				if got != !tc.want {
					t.Errorf("a rejected value changed the setting to %v", got)
				}
				return
			}
			if code != 200 || got != tc.want {
				t.Errorf("status = %d, autoblock.enabled = %v, want 200 and %v", code, got, tc.want)
			}
		})
	}
}

// One unreadable value refuses the whole request: nothing from it is applied.
func TestSettingsPutUnreadableValueAppliesNothing(t *testing.T) {
	s := settingsTestServer(t)
	s.config.Global.LogLevel = "info"
	code, body := putSettingsStatus(s, `{"global.log_level": "debug", "global.timeouts.write": "soon", "global.cache.default_ttl": "1h"}`)
	if code != 400 {
		t.Fatalf("status = %d, want 400", code)
	}
	for _, k := range []string{"global.timeouts.write", "global.cache.default_ttl"} {
		if !strings.Contains(body, k) {
			t.Errorf("response %q does not name %s", body, k)
		}
	}
	if s.config.Global.LogLevel != "info" {
		t.Errorf("log_level = %q: a refused request applied part of itself", s.config.Global.LogLevel)
	}
}
