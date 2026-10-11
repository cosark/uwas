package config

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// F14100: configs and documentation that users copy must load with the schema
// the server actually has. test/perf/uwas-perf.yaml carried a key the schema
// does not know (silently ignored, since F13504 reported as a warning), and
// three documentation blocks used a form the loader rejects outright
// (upstreams as bare strings, rotate.max_age: 30d, compression "brotli"/"zstd")
// or described an admin mutual-TLS option that does not exist.

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	return filepath.Join("..", "..", filepath.FromSlash(rel))
}

func TestShippedExampleConfigsLoadWithoutWarnings(t *testing.T) {
	// The WordPress example takes its settings from the environment the
	// compose file requires; load it the way compose would run it.
	t.Setenv("ADMIN_EMAIL", "admin@example.com")
	t.Setenv("DOMAIN", "example.com")
	t.Setenv("SSL_MODE", "auto")
	t.Setenv("UWAS_ADMIN_KEY", "example-admin-key-0123456789")

	files := []string{
		"uwas.example.yaml",
		"docker/uwas.yaml",
		"examples/multi-domain/uwas.yaml",
		"examples/wordpress/config/uwas.yaml",
		"test/e2e/uwas-e2e.yaml",
		"test/docker/uwas-test.yaml",
		"test/perf/uwas-perf.yaml",
		"test/autoblock-lab/uwas-lab.yaml",
	}
	for _, rel := range files {
		path := repoFile(t, rel)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s: shipped example is missing: %v", rel, err)
			continue
		}
		cfg, err := Load(path)
		if err != nil {
			t.Errorf("%s: does not load: %v", rel, err)
			continue
		}
		for _, w := range cfg.Warnings {
			t.Errorf("%s: loads with a warning (a key the schema does not know): %s", rel, w)
		}
	}
}

var yamlFence = regexp.MustCompile("(?s)```ya?ml\\n(.*?)```")

// TestDocumentedConfigBlocksMatchTheSchema decodes every YAML block in the
// main documents that is shaped like a whole config (it has a top-level
// "global" or "domains" key) strictly and validates it, so a copy-pasted
// example cannot name a key or a value form the server rejects.
func TestDocumentedConfigBlocksMatchTheSchema(t *testing.T) {
	docs := []string{
		"README.md",
		"ARCHITECTURE.md",
		"docs/SPECIFICATION.md",
		"docs/ddos-autoblock.md",
		"docker/README.md",
		"examples/multi-domain/README.md",
		"examples/wordpress/README.md",
	}
	checked := 0
	for _, rel := range docs {
		data, err := os.ReadFile(repoFile(t, rel))
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			continue
		}
		for i, m := range yamlFence.FindAllSubmatch(data, -1) {
			body := m[1]
			var top map[string]any
			if yaml.Unmarshal(body, &top) != nil {
				continue // not a plain mapping (compose files, lists, fragments)
			}
			_, hasGlobal := top["global"]
			_, hasDomains := top["domains"]
			if !hasGlobal && !hasDomains {
				continue
			}
			// A block that mixes in another schema (an app definition shown
			// next to a domains: block, for instance) is not a config.
			if !onlyConfigKeys(top) {
				continue
			}
			checked++
			line := 1 + bytes.Count(data[:bytes.Index(data, m[0])], []byte("\n"))
			where := rel + " block #" + strconv.Itoa(i+1) + " (line " + strconv.Itoa(line) + ")"

			var cfg Config
			dec := yaml.NewDecoder(bytes.NewReader(body))
			dec.KnownFields(true)
			if err := dec.Decode(&cfg); err != nil {
				t.Errorf("%s: does not decode against the schema: %s", where, strings.ReplaceAll(err.Error(), "\n", "; "))
				continue
			}
			if err := ValidateWithDefaults(&cfg); err != nil {
				t.Errorf("%s: fails validation: %s", where, strings.ReplaceAll(err.Error(), "\n", "; "))
			}
		}
	}
	if checked < 5 {
		t.Errorf("only %d config-shaped documentation blocks were found; the scan is not seeing the documents", checked)
	}
}

// onlyConfigKeys reports whether every top-level key of m is a key of Config.
func onlyConfigKeys(m map[string]any) bool {
	known := map[string]bool{}
	rt := reflect.TypeOf(Config{})
	for i := 0; i < rt.NumField(); i++ {
		name, _, _ := strings.Cut(rt.Field(i).Tag.Get("yaml"), ",")
		if name != "" && name != "-" {
			known[name] = true
		}
	}
	for k := range m {
		if !known[k] {
			return false
		}
	}
	return true
}
