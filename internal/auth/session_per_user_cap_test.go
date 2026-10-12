package auth

// R130 F18401: a valid login always added a session and nothing bounded how
// many one account could hold. Every login rewrites and fsyncs the whole
// sessions.json, so a low-privilege account looping on /auth/login grew the
// session map, the file and the per-login write cost without limit until the
// 24h TTL expired them.

import "testing"

func TestSessionsPerUserAreBounded(t *testing.T) {
	m := mustManager(t, t.TempDir())
	for _, name := range []string{"loopy", "bystander"} {
		if _, err := m.CreateUser(name, name+"@example.test", "pw-correct-horse", RoleUser, []string{"a.example"}); err != nil {
			t.Fatal(err)
		}
	}
	by, err := m.Authenticate("bystander", "pw-correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	var first, last *Session
	n := maxSessionsPerUser + 10
	for i := 0; i < n; i++ {
		s, err := m.Authenticate("loopy", "pw-correct-horse")
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = s
		}
		last = s
	}
	m.mu.RLock()
	held := 0
	for _, s := range m.sessions {
		if s.Username == "loopy" {
			held++
		}
	}
	m.mu.RUnlock()
	if held > maxSessionsPerUser {
		t.Fatalf("one account holds %d sessions after %d logins (cap %d)", held, n, 50)
	}
	// The newest session works, the oldest was evicted, other accounts are untouched.
	if _, err := m.ValidateSession(last.Token); err != nil {
		t.Errorf("newest session rejected: %v", err)
	}
	if _, err := m.ValidateSession(first.Token); err == nil {
		t.Errorf("oldest session survived the cap")
	}
	if _, err := m.ValidateSession(by.Token); err != nil {
		t.Errorf("another account's session was evicted: %v", err)
	}
}
