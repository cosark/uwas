package auth

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// F15502: users.json, the JWT secret and sessions.json were published with
// write+rename and no fsync, so a power loss could leave a zero-length file
// that fails to parse and locks every account out. Each write must flush the
// temp file while the live file still holds the previous content, i.e. before
// the rename.
func TestAuthStateFilesAreFlushedBeforeRename(t *testing.T) {
	dir := t.TempDir()
	var mu sync.Mutex
	flushed := map[string]int{}
	afterRename := map[string]int{}
	old := syncFile
	syncFile = func(f *os.File) error {
		name := filepath.Base(f.Name())
		mu.Lock()
		defer mu.Unlock()
		flushed[name]++
		live := filepath.Join(dir, name[:len(name)-len(".tmp")])
		if a, err := os.ReadFile(live); err == nil {
			if b, _ := os.ReadFile(f.Name()); len(b) > 0 && string(a) == string(b) {
				afterRename[name]++
			}
		}
		return old(f)
	}
	defer func() { syncFile = old }()

	m, err := NewManager(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	if _, err := m.CreateUser("alice", "", "alice-pass-1", RoleAdmin, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Authenticate("alice", "alice-pass-1"); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, want := range []string{"users.json.tmp", "sessions.json.tmp"} {
		if flushed[want] == 0 {
			t.Errorf("%s was renamed into place without a flush; flushed=%v", want, flushed)
		}
	}
	secret := filepath.Base(m.secretFile()) + ".tmp"
	if flushed[secret] == 0 {
		t.Errorf("JWT secret file was renamed into place without a flush; flushed=%v", flushed)
	}
	for name, n := range afterRename {
		t.Errorf("%s was flushed %d time(s) after its content was already live", name, n)
	}
}

// A failing fsync must fail the save, not publish a possibly torn file. The
// previous users.json stays intact.
func TestUsersSaveFailsWhenFlushFails(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	if _, err := m.CreateUser("alice", "", "alice-pass-1", RoleAdmin, nil); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}

	old := syncFile
	syncFile = func(*os.File) error { return os.ErrInvalid }
	defer func() { syncFile = old }()
	if _, err := m.CreateUser("bob", "", "bob-pass-12", RoleUser, nil); err == nil {
		t.Fatal("CreateUser reported success although the flush failed")
	}
	after, err := os.ReadFile(filepath.Join(dir, "users.json"))
	if err != nil || string(after) != string(before) {
		t.Fatalf("users.json changed by a save whose flush failed: err=%v", err)
	}
}
