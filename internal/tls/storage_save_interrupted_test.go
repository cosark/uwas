package uwastls

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// F8500: Save renames key.pem then cert.pem; a crash between them left a new
// key beside the old cert, Load rejected the pair and the domain lost its
// certificate. Save now keeps the replaced pair as .prev until both renames
// are done and Load falls back to it.
func TestCertStorageInterruptedSaveKeepsPreviousPair(t *testing.T) {
	st := NewCertStorage(t.TempDir())
	c1, cert1, key1 := generateTestCert(t, "x.example.com")
	c2, cert2, key2 := generateTestCert(t, "x.example.com")
	if err := st.Save("x.example.com", c1, key1, cert1); err != nil {
		t.Fatal(err)
	}

	afterKeyRename = func() error { return errors.New("simulated crash") }
	err := st.Save("x.example.com", c2, key2, cert2)
	afterKeyRename = nil
	if err == nil {
		t.Fatal("interrupted Save returned nil")
	}

	got, lerr := st.Load("x.example.com")
	if lerr != nil {
		t.Fatalf("Load after interrupted Save: %v", lerr)
	}
	if !bytes.Equal(got.Certificate[0], c1.Certificate[0]) {
		t.Error("Load did not fall back to the previous (complete) pair")
	}
}

func TestCertStorageCompletedSaveDropsPreviousPair(t *testing.T) {
	dir := t.TempDir()
	st := NewCertStorage(dir)
	c1, cert1, key1 := generateTestCert(t, "y.example.com")
	c2, cert2, key2 := generateTestCert(t, "y.example.com")
	if err := st.Save("y.example.com", c1, key1, cert1); err != nil {
		t.Fatal(err)
	}
	if err := st.Save("y.example.com", c2, key2, cert2); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"key.pem.prev", "cert.pem.prev"} {
		if _, err := os.Stat(filepath.Join(dir, "y.example.com", n)); !os.IsNotExist(err) {
			t.Errorf("%s left behind after a completed Save (old private key retained): %v", n, err)
		}
	}
	got, err := st.Load("y.example.com")
	if err != nil || !bytes.Equal(got.Certificate[0], c2.Certificate[0]) {
		t.Fatalf("completed Save does not load the new pair: %v", err)
	}
}

func TestCertStorageMismatchedPairWithoutPrevStillFails(t *testing.T) {
	dir := t.TempDir()
	st := NewCertStorage(dir)
	c1, cert1, key1 := generateTestCert(t, "z.example.com")
	_, _, key2 := generateTestCert(t, "z.example.com")
	if err := st.Save("z.example.com", c1, key1, cert1); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "z.example.com", "key.pem"), key2, 0600)
	if _, err := st.Load("z.example.com"); err == nil {
		t.Fatal("mismatched pair with no previous pair must not load")
	}
}
