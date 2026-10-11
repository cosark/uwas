package sftpserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testHostKeyPEM(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// F15500: only a missing key file means "generate one". A key that exists but
// cannot be read must not be replaced: the old code generated a new identity
// and overwrote the real one, so every client saw a host-key change.
func TestHostKeyReadErrorDoesNotReplaceTheIdentity(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file modes")
	}
	path := filepath.Join(t.TempDir(), "sftp_host_key")
	want := testHostKeyPEM(t)
	if err := os.WriteFile(path, want, 0o200); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o200); err != nil {
		t.Fatal(err)
	}
	s := New(Config{HostKey: path}, testLogger())
	if _, err := s.loadOrGenerateHostKey(); err == nil {
		t.Fatal("an unreadable host key was replaced by a new identity")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, want) {
		t.Fatal("the unreadable host key file was overwritten")
	}
}

// F15501: two first starts that both saw "no key" must serve the identity that
// ends up persisted, not two different ones with only the last writer kept.
func TestHostKeyConcurrentFirstStartsConverge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sftp_host_key")
	var arrived atomic.Int32
	var both sync.WaitGroup
	both.Add(2)
	firstDone := make(chan struct{})
	hostKeyBeforePersist = func() {
		n := arrived.Add(1)
		both.Done()
		both.Wait()
		if n == 2 {
			<-firstDone // the second publishes only after the first finished
		}
	}
	defer func() { hostKeyBeforePersist = nil }()

	type res struct {
		signer ssh.Signer
		err    error
	}
	out := make(chan res, 2)
	for i := 0; i < 2; i++ {
		go func() {
			sg, err := New(Config{HostKey: path}, testLogger()).loadOrGenerateHostKey()
			out <- res{sg, err}
		}()
	}
	r1 := <-out
	close(firstDone)
	r2 := <-out
	if r1.err != nil || r2.err != nil {
		t.Fatalf("start failed: %v / %v", r1.err, r2.err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := ssh.ParsePrivateKey(data)
	if err != nil {
		t.Fatal(err)
	}
	p := persisted.PublicKey().Marshal()
	if !bytes.Equal(r1.signer.PublicKey().Marshal(), p) || !bytes.Equal(r2.signer.PublicKey().Marshal(), p) {
		t.Fatal("a start is serving a host key that is not the persisted one")
	}
}

// The key file is published whole or not at all: no temp file is left behind,
// the mode is private, and an existing key is never replaced.
func TestPublishHostKeyIsAtomicAndNeverClobbers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sftp_host_key")
	first := testHostKeyPEM(t)
	won, err := publishHostKey(path, first)
	if err != nil || !won {
		t.Fatalf("first publish: won=%v err=%v", won, err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("host key mode = %v, want 0600", st.Mode().Perm())
	}
	won, err = publishHostKey(path, testHostKeyPEM(t))
	if err != nil || won {
		t.Fatalf("second publish: won=%v err=%v, want the existing key kept", won, err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, first) {
		t.Fatal("an existing host key was replaced")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}
