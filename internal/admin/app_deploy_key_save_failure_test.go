package admin

// F5001: GenerateDeployKey replaced id_ed25519 before saving the app config, so a
// failed save destroyed the key registered with the git host.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestAppGenerateDeployKeySaveFailureKeepsExistingKey(t *testing.T) {
	const old = "EXISTING-REGISTERED-KEY"
	// control: Save succeeds -> 200 and a new key
	s, keyPath := f4700setup(t, false)
	if code := f4700call(s); code != 200 {
		t.Fatalf("invalid proof: control code %d", code)
	}
	if b, _ := os.ReadFile(keyPath); string(b) == old {
		t.Fatal("invalid proof: control did not regenerate")
	}
	// defect: the apps store directory is not writable, so Save fails (500).
	s, keyPath = f4700setup(t, false)
	storeDir := filepath.Dir(filepath.Dir(filepath.Dir(keyPath)))
	if err := os.Chmod(storeDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(storeDir, 0o700) })
	if f, err := os.CreateTemp(storeDir, "probe"); err == nil {
		f.Close()
		t.Fatal("invalid proof: store dir still writable")
	}
	code := f4700call(s)
	b, _ := os.ReadFile(keyPath)
	same := bytes.Equal(b, []byte(old))
	if code != 500 {
		t.Errorf("code = %d, want 500 when the store cannot be saved", code)
	}
	if !same {
		t.Error("registered deploy key was replaced although the config was not saved (F5001)")
	}
}
