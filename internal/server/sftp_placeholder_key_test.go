package server

import (
	"crypto/sha256"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F16201: an SFTP password is an HMAC of the admin api_key and the domain
// name, so a placeholder key that ships in the docs makes every password
// computable by anyone who knows a hostname.
func TestSFTPUsersRefusePlaceholderKeys(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{Domains: []config.Domain{{Host: "a.test", Type: "static", Root: root}}}
	s := New(cfg, logger.New("error", "text"))
	users := func(key string) int {
		s.sftpMu.Lock()
		defer s.sftpMu.Unlock()
		return len(s.sftpUsersLocked(cfg.Domains, key))
	}
	const strong = "S7r0ng-unique-key-9f3c1a77d2"
	if n := users(strong); n != 1 {
		t.Fatalf("a unique key yielded %d SFTP users, want 1", n)
	}
	// The table was built from the password derived from the real key, not
	// from anything an outsider could compute (checked on the digest the
	// server keeps, which avoids a second bcrypt at the production cost).
	s.sftpMu.Lock()
	e, ok := s.sftpHashes["a.test"]
	s.sftpMu.Unlock()
	if !ok || e.sum != sha256.Sum256([]byte(deriveSFTPPassword(strong, "a.test"))) {
		t.Fatal("the SFTP table was not built from the password derived from the real key")
	}
	for _, k := range []string{"", "   ", "changeme", "please-change-this-admin-key", "admin", " Changeme "} {
		if n := users(k); n != 0 {
			t.Errorf("key %q yielded %d SFTP users, want none", k, n)
		}
	}
	// Falling back to a placeholder drops the table: nobody is left holding a
	// password derived from the previous key either.
	s.sftpMu.Lock()
	n := len(s.sftpHashes)
	s.sftpMu.Unlock()
	if n != 0 {
		t.Errorf("%d password digests survived a switch to a placeholder key", n)
	}
}
