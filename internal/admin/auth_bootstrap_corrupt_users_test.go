package admin

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/auth"
)

// A users.json that exists but cannot be parsed (a crash left it zero-length or
// torn) must keep the first-admin bootstrap closed. Treating it as "no users
// yet" would let whoever reaches the public bootstrap endpoint first become
// admin of the whole install. The corrupt file must also survive untouched so
// the operator can recover it.
func TestBootstrapStaysClosedWhenUsersFileIsCorrupt(t *testing.T) {
	for name, content := range map[string]string{
		"zero length":     "",
		"whitespace only": "\n  \n",
		"torn mid-record": `[{"id":"abc","username":"alice","password_hash":"$2a$1`,
		"truncated array": `[`,
	} {
		t.Run(name, func(t *testing.T) {
			s := testServer()
			s.config.Global.WebRoot = t.TempDir()
			s.config.Global.Users.Enabled = true
			s.config.Global.Admin.APIKey = ""
			usersPath := filepath.Join(s.config.Global.WebRoot, "users.json")
			if err := os.WriteFile(usersPath, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/api/v1/auth/bootstrap",
				strings.NewReader(`{"username":"attacker","email":"a@example.com","password":"S3cure-Passw0rd!"}`))
			req.RemoteAddr = "203.0.113.9:4444"
			s.authMiddleware(s.mux).ServeHTTP(rec, req)
			if rec.Code != 501 {
				t.Fatalf("bootstrap over a corrupt users.json = %d, want 501 (auth unavailable): %s", rec.Code, rec.Body.String())
			}
			if mgr, ok := s.authMgr.(*auth.Manager); ok {
				mgr.Stop()
				t.Fatalf("auth manager was built over a corrupt users.json (status %d)", rec.Code)
			}
			got, err := os.ReadFile(usersPath)
			if err != nil || string(got) != content {
				t.Fatalf("corrupt users.json was modified: err=%v content=%q", err, got)
			}
		})
	}

	// Control: without a users file the manager is built and the request reaches
	// the handler (a weak password is refused by policy before any hashing, so
	// the control stays fast). The 501s above therefore come from the corrupt
	// file, not from the setup.
	t.Run("control: no users file", func(t *testing.T) {
		s := testServer()
		s.config.Global.WebRoot = t.TempDir()
		s.config.Global.Users.Enabled = true
		s.config.Global.Admin.APIKey = ""
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/v1/auth/bootstrap",
			strings.NewReader(`{"username":"admin","email":"a@example.com","password":"short"}`))
		req.RemoteAddr = "10.0.0.1:1234"
		s.authMiddleware(s.mux).ServeHTTP(rec, req)
		if rec.Code != 400 {
			t.Fatalf("control bootstrap = %d, want 400 (policy refusal): %s", rec.Code, rec.Body.String())
		}
		mgr, ok := s.authMgr.(*auth.Manager)
		if !ok {
			t.Fatal("control: auth manager was not built")
		}
		mgr.Stop()
	})
}
