package auth

// R129 F18000: a session revoked in memory (user disabled, user deleted,
// password changed) must stay revoked after a restart even when sessions.json
// still holds the old token.
//
// Revocation touches two files: users.json (saved first) and sessions.json
// (saved after, and best-effort: writeSessions swallows every error). A crash
// between the two writes, or a failed sessions.json write (disk full,
// read-only filesystem), leaves the revoked token on disk. loadSessions then
// restored it, and the session middleware (ValidateSession + GetUserByID)
// authenticated a DISABLED user, or one whose password had just been changed
// because the old one leaked, with the old token.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func f18000Setup(t *testing.T) (dir string, m *Manager, token string) {
	t.Helper()
	dir = t.TempDir()
	m = mustManager(t, dir)
	if _, err := m.CreateUser("victim", "v@example.test", "pw-correct-horse", RoleReseller, []string{"a.example"}); err != nil {
		t.Fatal(err)
	}
	s, err := m.Authenticate("victim", "pw-correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	return dir, m, s.Token
}

// stale simulates the crash window: users.json already carries the revocation
// while sessions.json still holds the session that was valid before it.
func f18000StaleSessions(t *testing.T, dir string, snapshot []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "sessions.json"), snapshot, 0o600); err != nil {
		t.Fatal(err)
	}
}

func f18000Restart(t *testing.T, dir string, old *Manager) *Manager {
	t.Helper()
	old.Stop()
	m2, err := NewManager(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m2.Stop)
	return m2
}

// sessionAdmits mirrors the session path of the admin middleware.
func f18000Admits(m *Manager, token string) (bool, *User) {
	s, err := m.ValidateSession(token)
	if err != nil {
		return false, nil
	}
	u, ok := m.GetUserByID(s.UserID)
	if !ok {
		return false, nil
	}
	return true, u
}

func TestSessionRevocationSurvivesRestart(t *testing.T) {
	t.Run("control: untouched user keeps its session across restart", func(t *testing.T) {
		dir, m, token := f18000Setup(t)
		m2 := f18000Restart(t, dir, m)
		if ok, _ := f18000Admits(m2, token); !ok {
			t.Fatal("a valid session must survive a restart")
		}
	})

	t.Run("disable with sessions.json write failure", func(t *testing.T) {
		dir, m, token := f18000Setup(t)
		orig := syncFile
		syncFile = func(f *os.File) error {
			if strings.HasPrefix(filepath.Base(f.Name()), "sessions.json") {
				return errors.New("ENOSPC")
			}
			return orig(f)
		}
		t.Cleanup(func() { syncFile = orig })

		if err := m.UpdateUser("victim", &User{EnabledSet: true, Enabled: false}); err != nil {
			t.Fatal(err)
		}
		if ok, _ := f18000Admits(m, token); ok {
			t.Fatal("control: in-memory session must be revoked by disable")
		}
		m2 := f18000Restart(t, dir, m)
		if ok, u := f18000Admits(m2, token); ok {
			t.Fatalf("PROBLEM: disabled user %q (enabled=%v) is admitted with the pre-disable token after restart", u.Username, u.Enabled)
		}
	})

	t.Run("delete in the crash window", func(t *testing.T) {
		dir, m, token := f18000Setup(t)
		snap, err := os.ReadFile(filepath.Join(dir, "sessions.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := m.DeleteUser("victim"); err != nil {
			t.Fatal(err)
		}
		f18000StaleSessions(t, dir, snap)
		m2 := f18000Restart(t, dir, m)
		if ok, _ := f18000Admits(m2, token); ok {
			t.Fatal("PROBLEM: session of a deleted user is admitted after restart")
		}
	})

	t.Run("password change in the crash window", func(t *testing.T) {
		dir, m, token := f18000Setup(t)
		snap, err := os.ReadFile(filepath.Join(dir, "sessions.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := m.UpdateUser("victim", &User{Password: "pw-new-correct-horse"}); err != nil {
			t.Fatal(err)
		}
		if ok, _ := f18000Admits(m, token); ok {
			t.Fatal("control: in-memory session must be revoked by a password change")
		}
		f18000StaleSessions(t, dir, snap)
		m2 := f18000Restart(t, dir, m)
		if ok, _ := f18000Admits(m2, token); ok {
			t.Fatal("PROBLEM: token issued before a password change is admitted after restart")
		}
		// The new password still logs in.
		if _, err := m2.Authenticate("victim", "pw-new-correct-horse"); err != nil {
			t.Fatalf("new password must log in: %v", err)
		}
	})

	t.Run("self-service password change in the crash window", func(t *testing.T) {
		dir, m, token := f18000Setup(t)
		snap, _ := os.ReadFile(filepath.Join(dir, "sessions.json"))
		if err := m.ChangePassword("victim", "pw-correct-horse", "pw-another-horse-1"); err != nil {
			t.Fatal(err)
		}
		f18000StaleSessions(t, dir, snap)
		m2 := f18000Restart(t, dir, m)
		if ok, _ := f18000Admits(m2, token); ok {
			t.Fatal("PROBLEM: token issued before ChangePassword is admitted after restart")
		}
	})
}

// A live session must follow the user record: a demotion or a domain removal
// applies to the very next request, not at the next login (characterization).
func TestSessionFollowsRoleAndDomainChanges(t *testing.T) {
	_, m, token := f18000Setup(t)
	t.Cleanup(m.Stop)
	ok, u := f18000Admits(m, token)
	if !ok || u.Role != RoleReseller || !m.CanManageDomain(u, "a.example") {
		t.Fatalf("setup: admits=%v user=%+v", ok, u)
	}
	if err := m.UpdateUser("victim", &User{Role: RoleUser, Domains: []string{"z.example"}}); err != nil {
		t.Fatal(err)
	}
	ok, u = f18000Admits(m, token)
	if !ok {
		t.Fatal("a role change must not log the user out")
	}
	if u.Role != RoleUser || m.CanManageDomain(u, "a.example") || !m.CanManageDomain(u, "z.example") {
		t.Fatalf("session still carries the old grants: role=%s domains=%v", u.Role, u.Domains)
	}
}

// Username spellings other than the stored one are different (non-existent)
// accounts: they never authenticate, and failures on them do not lock the real
// account of the same client (and vice versa).
func TestLoginUsernameVariantsDoNotShareOrBypassLockout(t *testing.T) {
	_, m, _ := f18000Setup(t)
	t.Cleanup(m.Stop)
	const ip = "203.0.113.7"
	for _, v := range []string{"VICTIM", "Victim", "victim ", " victim", "victim\x00", "victim\u200b"} {
		if _, err := m.AuthenticateFrom(v, "pw-correct-horse", ip); err == nil {
			t.Fatalf("variant %q authenticated as the real account", v)
		}
	}
	if _, err := m.AuthenticateFrom("victim", "pw-correct-horse", ip); err != nil {
		t.Fatalf("variant failures locked the real account: %v", err)
	}
	// Five wrong passwords on the real name lock that (name, IP) pair, and no
	// spelling of the name gets around it.
	for i := 0; i < maxLoginAttempts; i++ {
		_, _ = m.AuthenticateFrom("victim", "wrong-password-x", ip)
	}
	if _, err := m.AuthenticateFrom("victim", "pw-correct-horse", ip); err == nil {
		t.Fatal("locked pair accepted the correct password")
	}
	for _, v := range []string{"VICTIM", "victim ", "Victim"} {
		if _, err := m.AuthenticateFrom(v, "pw-correct-horse", ip); err == nil {
			t.Fatalf("variant %q authenticated while the real pair is locked", v)
		}
	}
}
