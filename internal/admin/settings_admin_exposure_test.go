package admin

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F16400: Start refuses to bind the admin API on a public address without
// credentials, or behind a well-known placeholder key ("changeme"), because
// that exposes the whole API to anyone. A live PUT /settings did not look: the
// key is rotated on the running server at once (F2170) and the change is saved,
// so a public admin API could be left open or guessable by one request, and a
// saved change of that kind makes the next start refuse to bring the admin API
// up (the process only logs the error).
func TestSettingsPutKeepsAPublicAdminAPIGuarded(t *testing.T) {
	type row struct {
		name    string
		listen  string
		key     string
		users   bool
		payload string
		reject  bool
	}
	for _, tc := range []row{
		{"strong key on a public listener (control)", "0.0.0.0:9443", "k-7f3a91c04b2d5e86a1c9d03b", false, `{"global.admin.api_key": "another-strong-key-7a1b9c3d5e"}`, false},
		{"placeholder key on a public listener", "0.0.0.0:9443", "k-7f3a91c04b2d5e86a1c9d03b", false, `{"global.admin.api_key": "changeme"}`, true},
		{"placeholder key, other spelling and case", "0.0.0.0:9443", "k-7f3a91c04b2d5e86a1c9d03b", false, `{"global.admin.api_key": " Admin "}`, true},
		{"clearing the only credential on a public listener", "0.0.0.0:9443", "k-7f3a91c04b2d5e86a1c9d03b", false, `{"global.admin.api_key": ""}`, true},
		{"clearing the key with multi-user auth on is fine", "0.0.0.0:9443", "k-7f3a91c04b2d5e86a1c9d03b", true, `{"global.admin.api_key": ""}`, false},
		{"placeholder key on loopback is fine", "127.0.0.1:9443", "k-7f3a91c04b2d5e86a1c9d03b", false, `{"global.admin.api_key": "changeme"}`, false},
		{"clearing the key on loopback is fine", "127.0.0.1:9443", "k-7f3a91c04b2d5e86a1c9d03b", false, `{"global.admin.api_key": ""}`, false},
		{"going public with no credentials", "127.0.0.1:9443", "", false, `{"global.admin.listen": "0.0.0.0:9443"}`, true},
		{"going public with a placeholder key", "127.0.0.1:9443", "changeme", false, `{"global.admin.listen": ":9443"}`, true},
		{"going public with a strong key (control)", "127.0.0.1:9443", "k-7f3a91c04b2d5e86a1c9d03b", false, `{"global.admin.listen": "0.0.0.0:9443"}`, false},
		{"turning multi-user auth off on a public listener with no key", "0.0.0.0:9443", "", true, `{"global.users.enabled": false}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := settingsTestServer(t)
			s.config.Global.Admin.Listen = tc.listen
			s.config.Global.Admin.APIKey = tc.key
			s.config.Global.Users.Enabled = tc.users
			code, body := putSettingsStatus(s, tc.payload)
			if tc.reject {
				if code != 400 {
					t.Fatalf("status = %d (%s), want 400", code, body)
				}
				if s.config.Global.Admin.APIKey != tc.key || s.config.Global.Admin.Listen != tc.listen || s.config.Global.Users.Enabled != tc.users {
					t.Errorf("a refused change was applied: key=%q listen=%q users=%v", s.config.Global.Admin.APIKey, s.config.Global.Admin.Listen, s.config.Global.Users.Enabled)
				}
				if !strings.Contains(body, "admin") {
					t.Errorf("the refusal does not say why: %q", body)
				}
				return
			}
			if code != 200 {
				t.Fatalf("status = %d (%s), want 200", code, body)
			}
		})
	}
}

// F16400, raw editor: the same refusal applies to a saved YAML. Reload applies
// the key to the running server, so a file that leaves a public admin API
// without credentials or behind a placeholder key is refused before it is
// written.
func TestConfigRawPutKeepsAPublicAdminAPIGuarded(t *testing.T) {
	put := func(t *testing.T, current, content string) (int, string, string) {
		t.Helper()
		cfgPath := filepath.Join(t.TempDir(), "uwas.yaml")
		if err := os.WriteFile(cfgPath, []byte(current), 0o600); err != nil {
			t.Fatal(err)
		}
		s := testServer()
		s.SetConfigPath(cfgPath)
		s.config.Global.Admin.Listen = "0.0.0.0:9443"
		s.config.Global.Admin.APIKey = "k-7f3a91c04b2d5e86a1c9d03b"
		jsonBody, _ := json.Marshal(map[string]string{"content": content})
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, withAdminContext(httptest.NewRequest("PUT", "/api/v1/config/raw", strings.NewReader(string(jsonBody)))))
		onDisk, _ := os.ReadFile(cfgPath)
		return rec.Code, rec.Body.String(), string(onDisk)
	}
	const good = "global:\n  admin:\n    listen: 0.0.0.0:9443\n    api_key: k-7f3a91c04b2d5e86a1c9d03b\n"

	t.Run("control: a strong key on a public listener is saved", func(t *testing.T) {
		code, body, _ := put(t, good, "global:\n  admin:\n    listen: 0.0.0.0:9443\n    api_key: another-strong-key-7a1b9c3d5e\n")
		if code != 200 {
			t.Fatalf("status = %d, want 200; body %s", code, body)
		}
	})
	for _, c := range []struct{ name, content string }{
		{"placeholder key", "global:\n  admin:\n    listen: 0.0.0.0:9443\n    api_key: changeme\n"},
		{"no key and no multi-user auth", "global:\n  admin:\n    listen: 0.0.0.0:9443\n"},
		{"going public without credentials", "global:\n  admin:\n    listen: 0.0.0.0:9443\n    api_key: \"\"\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, body, onDisk := put(t, good, c.content)
			if code != 400 {
				t.Fatalf("status = %d (%s), want 400", code, body)
			}
			if onDisk != good {
				t.Errorf("a refused config was written: %q", onDisk)
			}
		})
	}
}
