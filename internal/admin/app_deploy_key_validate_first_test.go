package admin

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/uwaserver/uwas/internal/apps"
)

func f4700setup(t *testing.T, bad bool) (*Server, string) {
	s := testServer()
	dir := filepath.Join(t.TempDir(), "apps.d")
	store := apps.NewStore(dir)
	mgr := apps.NewManager(store, nil)
	s.SetAppsManager(mgr)
	if err := mgr.Register(&apps.App{Name: "keyed", Runtime: apps.RuntimeNode, WorkDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	def, err := store.Get("keyed")
	if err != nil || def == nil {
		t.Fatalf("get: %v %v", def, err)
	}
	if bad { // state that current validation rejects (e.g. hand-edited YAML)
		def.Deploy.GitURL = "git@github.com:example/private.git"
		def.Deploy.GitToken = "ghp_x"
		if err := store.Save(def); err != nil {
			t.Fatalf("invalid proof: cannot store bad state: %v", err)
		}
	}
	keyPath := filepath.Join(dir, "deploy-keys", "keyed", "id_ed25519")
	os.MkdirAll(filepath.Dir(keyPath), 0700)
	if err := os.WriteFile(keyPath, []byte("EXISTING-REGISTERED-KEY"), 0600); err != nil {
		t.Fatal(err)
	}
	return s, keyPath
}

func f4700call(s *Server) int {
	req := httptest.NewRequest("POST", "/api/v1/apps/keyed/deploy-key", nil)
	req.SetPathValue("name", "keyed")
	rec := httptest.NewRecorder()
	s.handleAppGenerateDeployKey(rec, withAdminContext(req))
	return rec.Code
}

// F4700: GenerateDeployKey replaced the existing id_ed25519 before validating
// the config, so a rejected request destroyed the registered key and never
// returned the new public key.
func TestAppGenerateDeployKeyRejectedConfigKeepsExistingKey(t *testing.T) {
	const old = "EXISTING-REGISTERED-KEY"
	// control: a valid config regenerates the key and answers 200
	s, keyPath := f4700setup(t, false)
	if code := f4700call(s); code != 200 {
		t.Fatalf("control code = %d, want 200", code)
	}
	if b, _ := os.ReadFile(keyPath); string(b) == old {
		t.Fatal("control did not regenerate the key")
	}
	// a config the validator rejects must leave the existing key alone
	s, keyPath = f4700setup(t, true)
	if code := f4700call(s); code != 400 {
		t.Fatalf("code = %d, want 400", code)
	}
	if b, _ := os.ReadFile(keyPath); string(b) != old {
		t.Fatalf("existing deploy key was replaced by a rejected request: %q", b)
	}
}
