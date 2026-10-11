package admin

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/auth"
	"github.com/uwaserver/uwas/internal/config"
)

// F12000: the raw YAML editor validates with the loader, which accepts an
// operator-written php.env.PHP_ADMIN_VALUE. A non-admin must not be able to
// persist the ini directives (sendmail_path, ffi.preload, ...) the JSON update
// refuses; an admin keeps the operator workflow.
func TestRawEditorRefusesPHPEnvDirectivesForNonAdmins(t *testing.T) {
	newEnv := func() *hostConflictEnv {
		return newHostConflictEnv(t, []config.Domain{{Host: "reseller.com", Type: "php"}})
	}
	persisted := func(e *hostConflictEnv) string {
		var out strings.Builder
		files, _ := filepath.Glob(filepath.Join(filepath.Dir(e.cfgPath), "domains.d", "*.yaml"))
		for _, f := range files {
			b, _ := os.ReadFile(f)
			out.Write(b)
		}
		return out.String()
	}
	raw := func(e *hostConflictEnv, role auth.Role, envYAML string) int {
		y := "host: reseller.com\ntype: php\nroot: " + e.s.config.Domains[0].Root + "\nssl:\n  mode: \"off\"\nphp:\n  env:\n" + envYAML
		b, _ := json.Marshal(map[string]string{"content": y})
		return e.do(http.MethodPut, "/api/v1/config/domains/reseller.com/raw", string(b), role, "reseller.com")
	}

	for _, key := range []string{"PHP_ADMIN_VALUE", "PHP_VALUE", "PHP_INI_SCAN_DIR"} {
		e := newEnv()
		if code := raw(e, auth.RoleReseller, "    "+key+": \"ffi.preload=/tmp/x.h\"\n"); code != http.StatusBadRequest {
			t.Errorf("reseller raw %s: status = %d, want 400", key, code)
		}
		if strings.Contains(persisted(e), key) {
			t.Errorf("reseller raw %s: a refused request persisted the key", key)
		}
	}

	t.Run("harmless env key still accepted", func(t *testing.T) {
		e := newEnv()
		if code := raw(e, auth.RoleReseller, "    APP_ENV: production\n"); code != http.StatusOK {
			t.Errorf("reseller raw APP_ENV: status = %d, want 200", code)
		}
	})
	t.Run("admin keeps the operator workflow", func(t *testing.T) {
		e := newEnv()
		if code := raw(e, auth.RoleAdmin, "    PHP_ADMIN_VALUE: \"memory_limit=256M\"\n"); code != http.StatusOK {
			t.Errorf("admin raw PHP_ADMIN_VALUE: status = %d, want 200", code)
		}
	})
}
