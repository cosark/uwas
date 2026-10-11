package siteuser

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func symlinkTestKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}

func symlinkTestEnv(t *testing.T) (webDir, authKeys, victim string) {
	t.Helper()
	oldExec := execCommandFn
	execCommandFn = func(string, ...string) *exec.Cmd { return exec.Command("true") }
	t.Cleanup(func() { execCommandFn = oldExec })
	base := t.TempDir()
	webDir = filepath.Join(base, "example.com", "public_html")
	sshDir := filepath.Join(base, "example.com", ".ssh")
	if err := os.MkdirAll(webDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return webDir, filepath.Join(sshDir, "authorized_keys"), filepath.Join(base, "root_authorized_keys")
}

// F5900: the tenant owns .ssh and can replace authorized_keys with a symlink to
// a file only root may write (root's own authorized_keys). The privileged key
// add/remove/list must not follow it.
func TestAuthorizedKeysSymlinkIsNotFollowed(t *testing.T) {
	t.Run("add", func(t *testing.T) {
		webDir, authKeys, victim := symlinkTestEnv(t)
		orig := "ORIGINAL-ROOT-KEY\n"
		os.WriteFile(victim, []byte(orig), 0o600)
		if err := os.Symlink(victim, authKeys); err != nil {
			t.Fatal(err)
		}
		if err := AddSSHKeyForWebDir(webDir, "example.com", symlinkTestKey(t)); err == nil {
			t.Error("add through a symlinked authorized_keys succeeded")
		}
		if got, _ := os.ReadFile(victim); string(got) != orig {
			t.Errorf("file behind the symlink changed: %q", got)
		}
	})

	t.Run("remove", func(t *testing.T) {
		webDir, authKeys, victim := symlinkTestEnv(t)
		key := symlinkTestKey(t)
		orig := "KEEP-1\n" + key + "\nKEEP-2\n"
		os.WriteFile(victim, []byte(orig), 0o600)
		if err := os.Symlink(victim, authKeys); err != nil {
			t.Fatal(err)
		}
		if err := RemoveSSHKeyForWebDir(webDir, "example.com", key); err == nil {
			t.Error("remove through a symlinked authorized_keys succeeded")
		}
		if got, _ := os.ReadFile(victim); string(got) != orig {
			t.Errorf("file behind the symlink changed: %q", got)
		}
	})

	t.Run("list", func(t *testing.T) {
		webDir, authKeys, victim := symlinkTestEnv(t)
		os.WriteFile(victim, []byte("root:$6$secret-hash:::\n"), 0o600)
		if err := os.Symlink(victim, authKeys); err != nil {
			t.Fatal(err)
		}
		if got := ListSSHKeysForWebDir(webDir, "example.com"); len(got) != 0 {
			t.Errorf("listed lines read through the symlink: %q", got)
		}
	})
}

// Control: a regular authorized_keys is still added to and pruned, atomically
// (mode 0600, no temp file left behind).
func TestAuthorizedKeysRegularFileStillManaged(t *testing.T) {
	webDir, authKeys, _ := symlinkTestEnv(t)
	k1, k2 := symlinkTestKey(t), symlinkTestKey(t)
	for _, k := range []string{k1, k2} {
		if err := AddSSHKeyForWebDir(webDir, "example.com", k); err != nil {
			t.Fatalf("add: %v", err)
		}
	}
	if err := RemoveSSHKeyForWebDir(webDir, "example.com", k1); err != nil {
		t.Fatalf("remove: %v", err)
	}
	got := ListSSHKeysForWebDir(webDir, "example.com")
	if len(got) != 1 || got[0] != k2 {
		t.Fatalf("keys after remove = %q, want only %q", got, k2)
	}
	info, err := os.Stat(authKeys)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("authorized_keys mode = %v (err %v), want 0600", info.Mode().Perm(), err)
	}
	entries, _ := os.ReadDir(filepath.Dir(authKeys))
	if len(entries) != 1 {
		t.Errorf(".ssh holds %d entries after remove, want only authorized_keys", len(entries))
	}
}
