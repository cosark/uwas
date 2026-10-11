package admin

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/uwaserver/uwas/internal/config"
)

// F16400 differential: whatever PUT /api/v1/settings answers 200 to must leave
// a configuration the loader accepts on the next start. Every key the handler
// switches on is driven with values the loader's validation is known to
// refuse; a 200 followed by an invalid saved configuration means the API
// stored something config.Load will reject, which stops the next start or
// reload.
func TestSettingsPutNeverSavesAConfigTheLoaderRejects(t *testing.T) {
	src, err := os.ReadFile("settings/handler.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(`case ("global\.[a-z0-9_.]+"(?:,\s*"global\.[a-z0-9_.]+")*):`).FindAllStringSubmatch(string(src), -1) {
		for _, k := range regexp.MustCompile(`"(global\.[a-z0-9_.]+)"`).FindAllStringSubmatch(m[1], -1) {
			seen[k[1]] = true
		}
	}
	var keys []string
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) < 60 {
		t.Fatalf("found only %d settings keys, the scan is broken", len(keys))
	}
	garbage := []any{"-5s", -1, "0.0.0.0/33", "not-an-address", "http://", "cloudfare", "Turkey", "   "}

	// One server for the whole run: every New starts worker goroutines that are
	// never stopped, and a package-wide goroutine dump (a test elsewhere reads
	// one into a 1 MiB buffer) grows with each one left behind.
	s := settingsTestServer(t)
	checked := 0
	for _, key := range keys {
		for _, v := range garbage {
			// A valid starting point: the handler saves a change to an
			// already invalid configuration as before, so an invalid
			// baseline would hide the very thing this test looks for.
			*s.config = validBaselineConfig()
			if err := baselineConfigError(s.config); err != nil {
				t.Fatalf("the baseline is not a valid configuration: %v", err)
			}
			payload, _ := json.Marshal(map[string]any{key: v})
			code, body := putSettingsStatus(s, string(payload))
			if code != 200 {
				continue
			}
			checked++
			data, err := yaml.Marshal(s.config)
			if err != nil {
				t.Fatal(err)
			}
			var probe config.Config
			if err := yaml.Unmarshal(data, &probe); err != nil {
				t.Errorf("%s=%v saved (%s) but the config does not re-read: %v", key, v, body, err)
				continue
			}
			if err := config.ValidateWithDefaults(&probe); err != nil {
				t.Errorf("%s=%v was answered 200 yet config.Load would reject the saved config: %v", key, v, err)
			}
		}
	}
	t.Logf("%d keys, %d accepted inputs checked", len(keys), checked)
}

func baselineConfigError(cfg *config.Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	var probe config.Config
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return err
	}
	return config.ValidateWithDefaults(&probe)
}

func validBaselineConfig() config.Config {
	return config.Config{Global: config.GlobalConfig{Admin: config.AdminConfig{
		Listen: "127.0.0.1:9443",
		APIKey: "k-7f3a91c04b2d5e86a1c9d03b",
	}}}
}
