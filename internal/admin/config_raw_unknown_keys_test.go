package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/auth"
	"github.com/uwaserver/uwas/internal/config"
)

// F13702: the raw YAML editor parsed with yaml.Unmarshal, which drops keys
// config.Config has no field for, and config.Load does the same on every
// start. A mistyped key (security.blocked_path, access_log.request_log) was
// saved and reloaded as if it were applied; the setting never existed.
func TestConfigRawPutRejectsUnknownKeys(t *testing.T) {
	put := func(t *testing.T, content string) (int, string, string) {
		t.Helper()
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "uwas.yaml")
		const original = "global:\n  log_level: info\n"
		if err := os.WriteFile(cfgPath, []byte(original), 0o644); err != nil {
			t.Fatal(err)
		}
		s := testServer()
		s.SetConfigPath(cfgPath)
		jsonBody, _ := json.Marshal(map[string]string{"content": content})
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, withAdminContext(httptest.NewRequest("PUT", "/api/v1/config/raw", strings.NewReader(string(jsonBody)))))
		onDisk, _ := os.ReadFile(cfgPath)
		return rec.Code, rec.Body.String(), string(onDisk)
	}

	t.Run("control: known keys are saved", func(t *testing.T) {
		code, body, _ := put(t, "global:\n  log_level: debug\n  access_log:\n    enabled: false\n")
		if code != 200 {
			t.Fatalf("status = %d, want 200; body %s", code, body)
		}
	})

	for _, c := range []struct {
		name, yaml, key string
	}{
		{"unknown global key", "global:\n  log_levl: debug\n", "log_levl"},
		{"unknown nested key", "global:\n  access_log:\n    request_log: true\n", "request_log"},
		{"misspelled domain security key", "domains:\n  - host: a.test\n    type: static\n    root: /var/www/a\n    security:\n      blocked_path:\n        - /private\n", "blocked_path"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, body, onDisk := put(t, c.yaml)
			if code != 400 {
				t.Fatalf("status = %d, want 400; body %s", code, body)
			}
			if !strings.Contains(body, c.key) {
				t.Errorf("error must name the key %q, got %s", c.key, body)
			}
			if strings.Contains(onDisk, c.key) {
				t.Errorf("a rejected edit was written to disk: %q", onDisk)
			}
		})
	}
}

// The per-domain raw editor shares the shape: a mistyped key was saved and
// loaded as if applied.
func TestDomainRawPutRejectsUnknownKeys(t *testing.T) {
	put := func(t *testing.T, extra string) (int, string) {
		t.Helper()
		e := newHostConflictEnv(t, []config.Domain{{Host: "a.com", Type: "static"}})
		y := "host: a.com\ntype: static\nroot: " + e.s.config.Domains[0].Root + "\nssl:\n  mode: \"off\"\n" + extra
		b, _ := json.Marshal(map[string]string{"content": y})
		code := e.do(http.MethodPut, "/api/v1/config/domains/a.com/raw", string(b), auth.RoleAdmin)
		var out strings.Builder
		files, _ := filepath.Glob(filepath.Join(filepath.Dir(e.cfgPath), "domains.d", "*.yaml"))
		for _, f := range files {
			data, _ := os.ReadFile(f)
			out.Write(data)
		}
		return code, out.String()
	}

	if code, _ := put(t, "security:\n  blocked_paths:\n    - /private\n"); code != http.StatusOK {
		t.Fatalf("control: a known key was refused, status = %d", code)
	}
	code, onDisk := put(t, "security:\n  blocked_path:\n    - /private\n")
	if code != http.StatusBadRequest {
		t.Errorf("misspelled key: status = %d, want 400", code)
	}
	if strings.Contains(onDisk, "blocked_path:") {
		t.Errorf("a rejected edit was persisted: %s", onDisk)
	}
}
