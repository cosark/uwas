package sftpserver

import (
	"testing"

	"github.com/uwaserver/uwas/internal/logger"
	"golang.org/x/crypto/bcrypt"
)

// F11001: the dummy compare for an unknown user ran at bcrypt.DefaultCost while
// the real per-domain hashes use a higher cost, so an unknown username was
// rejected many times faster than a known one and revealed which domains have
// SFTP enabled. The dummy must run at the cost of the configured hashes.
func TestDummyCompareFollowsConfiguredHashCost(t *testing.T) {
	low, err := bcrypt.GenerateFromPassword([]byte("a"), 4)
	if err != nil {
		t.Fatal(err)
	}
	high, err := bcrypt.GenerateFromPassword([]byte("b"), 6)
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{Users: map[string]User{
		"a.example": {Password: string(low), Root: t.TempDir()},
		"b.example": {Password: string(high), Root: t.TempDir()},
	}}, logger.New("error", "text"))

	if got := int(burnCost.Load()); got != 6 {
		t.Fatalf("dummy cost = %d, want the strongest configured hash cost 6", got)
	}
	if c, err := bcrypt.Cost(dummyHashFor(int(burnCost.Load()))); err != nil || c != 6 {
		t.Fatalf("dummy hash cost = %d (err %v), want 6", c, err)
	}

	// A reload that replaces the users re-targets the dummy.
	s.UpdateUsers(map[string]User{"a.example": {Password: string(low), Root: t.TempDir()}})
	if got := int(burnCost.Load()); got != 4 {
		t.Fatalf("after UpdateUsers dummy cost = %d, want 4", got)
	}
	burnPasswordCompare([]byte("anything")) // must not panic

	// No hashes configured (or only legacy plaintext entries): fall back to the default.
	s.UpdateUsers(map[string]User{"legacy.example": {Password: "plaintext", Root: t.TempDir()}})
	if got := int(burnCost.Load()); got != bcrypt.DefaultCost {
		t.Fatalf("with no bcrypt hashes dummy cost = %d, want %d", got, bcrypt.DefaultCost)
	}
}
