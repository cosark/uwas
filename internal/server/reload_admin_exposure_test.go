package server

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F16200: the admin API refuses a public listener without credentials or
// behind a placeholder key only when it binds, so a reload that swaps the key
// under an already-bound listener has to refuse the same states.
func exposureServer(t *testing.T, listen, key string, multi bool) (*Server, func(listen, key string, multi bool) string) {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "www")
	os.MkdirAll(root, 0o755)
	cfgPath := filepath.Join(dir, "uwas.yaml")
	yamlFor := func(listen, key string, multi bool) string {
		return fmt.Sprintf("global:\n  worker_count: \"1\"\n  log_level: error\n  log_format: text\n  web_root: %s\n  admin:\n    enabled: true\n    listen: \"%s\"\n    api_key: \"%s\"\n  users:\n    enabled: %v\ndomains:\n  - host: a.test\n    type: static\n    root: %s\n    ssl:\n      mode: \"off\"\n", root, listen, key, multi, root)
	}
	if err := os.WriteFile(cfgPath, []byte(yamlFor(listen, key, multi)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, logger.New("error", "text"))
	s.SetConfigPath(cfgPath)
	rewrite := func(listen, key string, multi bool) string {
		if err := os.WriteFile(cfgPath, []byte(yamlFor(listen, key, multi)), 0o600); err != nil {
			t.Fatal(err)
		}
		return key
	}
	return s, rewrite
}

func liveAdminKey(s *Server) string {
	mu := s.cfgMu()
	mu.RLock()
	defer mu.RUnlock()
	return s.config.Global.Admin.APIKey
}

func TestReloadRefusesExposedAdminCredentials(t *testing.T) {
	const strong = "S7r0ng-unique-key-9f3c1a77d2"
	const other = "An0ther-unique-key-77aa31be90"
	const public = "0.0.0.0:19443"
	t.Run("placeholder key under a bound public listener", func(t *testing.T) {
		s, rewrite := exposureServer(t, public, strong, false)
		rewrite(public, "changeme", false)
		if err := s.reload(); err == nil {
			t.Fatal("reload accepted a placeholder admin key on a public listener")
		}
		if got := liveAdminKey(s); got != strong {
			t.Fatalf("the refused reload still changed the live key to %q", got)
		}
	})
	t.Run("cleared key under a bound public listener", func(t *testing.T) {
		s, rewrite := exposureServer(t, public, strong, false)
		rewrite(public, "", false)
		if err := s.reload(); err == nil {
			t.Fatal("reload accepted an empty admin key on a public listener")
		}
		if got := liveAdminKey(s); got != strong {
			t.Fatalf("the refused reload still changed the live key to %q", got)
		}
	})
	t.Run("the listener a hand-edited file names does not matter", func(t *testing.T) {
		// The bound listener is public; pointing the file at loopback must not
		// make the weak key acceptable until the process restarts.
		s, rewrite := exposureServer(t, public, strong, false)
		rewrite("127.0.0.1:19443", "changeme", false)
		if err := s.reload(); err == nil {
			t.Fatal("reload trusted the new listen address, but the listener is still bound publicly")
		}
	})
	t.Run("a real key rotation is fine", func(t *testing.T) {
		s, rewrite := exposureServer(t, public, strong, false)
		rewrite(public, other, false)
		if err := s.reload(); err != nil {
			t.Fatalf("rotating to another strong key was refused: %v", err)
		}
		if got := liveAdminKey(s); got != other {
			t.Fatalf("live key = %q, want the rotated key", got)
		}
	})
	t.Run("multi-user mode with no legacy key is fine", func(t *testing.T) {
		s, rewrite := exposureServer(t, public, strong, true)
		rewrite(public, "", true)
		if err := s.reload(); err != nil {
			t.Fatalf("clearing the legacy key under multi-user mode was refused: %v", err)
		}
	})
	t.Run("loopback listener may keep a placeholder", func(t *testing.T) {
		s, rewrite := exposureServer(t, "127.0.0.1:19443", strong, false)
		rewrite("127.0.0.1:19443", "changeme", false)
		if err := s.reload(); err != nil {
			t.Fatalf("a placeholder key on loopback was refused: %v", err)
		}
	})
	t.Run("a start that was already exposed does not make every reload fail", func(t *testing.T) {
		// The admin API never came up on this combination, so there is no
		// bound listener to protect and a reload that changes something else
		// (here: nothing) must still go through.
		s, rewrite := exposureServer(t, public, "changeme", false)
		rewrite(public, "changeme", false)
		if err := s.reload(); err != nil {
			t.Fatalf("an already-exposed state made an unrelated reload fail: %v", err)
		}
	})
	t.Run("a reload may repair an exposed start, and the repair is then protected", func(t *testing.T) {
		s, rewrite := exposureServer(t, public, "changeme", false)
		rewrite(public, other, false)
		if err := s.reload(); err != nil {
			t.Fatalf("repairing an exposed configuration was refused: %v", err)
		}
		rewrite(public, "changeme", false)
		if err := s.reload(); err == nil {
			t.Fatal("going back to the placeholder after the repair was accepted")
		}
	})
}
