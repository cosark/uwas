package auth

// R130 F18400: a logout whose sessions.json write failed (disk full, quota,
// read-only filesystem) was never retried. writeSessions dropped the error, the
// in-memory token was gone, and the old token stayed on disk until some later
// unrelated session mutation happened to rewrite the file. A restart in that
// window brought the logged-out token back.

import (
	"errors"
	"os"
	"testing"
)

func TestLogoutPersistFailureIsRetried(t *testing.T) {
	t.Run("control: logout with a healthy disk survives restart", func(t *testing.T) {
		dir, m, token := f18000Setup(t)
		m.Logout(token)
		m2 := f18000Restart(t, dir, m)
		if ok, _ := f18000Admits(m2, token); ok {
			t.Fatal("logged-out token admitted after restart")
		}
	})

	t.Run("failed write is retried by the next sweep", func(t *testing.T) {
		dir, m, token := f18000Setup(t)
		orig := syncFile
		t.Cleanup(func() { syncFile = orig })
		syncFile = func(*os.File) error { return errors.New("injected: no space left on device") }
		m.Logout(token)
		// The disk recovers; nothing else mutates a session.
		syncFile = orig
		m.CleanupSessions()
		m2 := f18000Restart(t, dir, m)
		if ok, _ := f18000Admits(m2, token); ok {
			t.Fatal("logged-out token came back after restart: the failed sessions.json write was never retried")
		}
	})

	t.Run("a later successful write clears the retry", func(t *testing.T) {
		_, m, token := f18000Setup(t)
		orig := syncFile
		t.Cleanup(func() { syncFile = orig })
		syncFile = func(*os.File) error { return errors.New("injected") }
		m.Logout(token)
		syncFile = orig
		if _, err := m.Authenticate("victim", "pw-correct-horse"); err != nil {
			t.Fatal(err)
		}
		if m.sessionsDirty.Load() {
			t.Fatal("sessions still marked dirty after a successful write")
		}
	})
}
