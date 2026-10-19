package admin

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/uwaserver/uwas/internal/auth"
	"github.com/uwaserver/uwas/internal/config"
)

// A certificate upload writes cert.pem and key.pem as two renames. When the
// key write fails after cert.pem was replaced, the working pair on disk must
// not be left half-replaced (new cert + old key) — the next TLS reload would
// reject the domain's certificate.
func TestCertUploadKeyWriteFailureKeepsWorkingPair(t *testing.T) {
	e := newHostConflictEnv(t, []config.Domain{{Host: "site.test", Type: "static"}})
	dir := t.TempDir()
	certUploadDir = dir
	t.Cleanup(func() { certUploadDir = "/var/lib/uwas/certs" })

	hostDir := filepath.Join(dir, "site.test")
	if err := os.MkdirAll(hostDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostDir, "cert.pem"), []byte("WORKING-CERT"), 0o600); err != nil {
		t.Fatal(err)
	}
	// key.pem is a non-empty directory: the rename onto it fails.
	keyPath := filepath.Join(hostDir, "key.pem")
	if err := os.MkdirAll(filepath.Join(keyPath, "block"), 0o700); err != nil {
		t.Fatal(err)
	}

	cert, key := selfSignedPair(t, "site.test")
	b, _ := json.Marshal(map[string]string{"cert": cert, "key": key})
	if code := e.do(http.MethodPost, "/api/v1/certs/site.test/upload", string(b), auth.RoleAdmin); code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", code)
	}
	got, _ := os.ReadFile(filepath.Join(hostDir, "cert.pem"))
	if string(got) != "WORKING-CERT" {
		t.Fatalf("EXPECTED: cert.pem restored to WORKING-CERT after the key write failed\nACTUAL: cert.pem = %.40q", got)
	}
}

// Control: with nothing in the way the upload replaces both files.
func TestCertUploadSuccessReplacesBothFiles(t *testing.T) {
	e := newHostConflictEnv(t, []config.Domain{{Host: "site.test", Type: "static"}})
	dir := t.TempDir()
	certUploadDir = dir
	t.Cleanup(func() { certUploadDir = "/var/lib/uwas/certs" })

	cert, key := selfSignedPair(t, "site.test")
	b, _ := json.Marshal(map[string]string{"cert": cert, "key": key})
	if code := e.do(http.MethodPost, "/api/v1/certs/site.test/upload", string(b), auth.RoleAdmin); code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	gc, _ := os.ReadFile(filepath.Join(dir, "site.test", "cert.pem"))
	gk, _ := os.ReadFile(filepath.Join(dir, "site.test", "key.pem"))
	if string(gc) != cert || string(gk) != key {
		t.Fatalf("pair not written")
	}
}

// Edge: a first-ever upload (no previous cert) that fails on the key leaves no
// orphan cert.pem behind.
func TestCertUploadKeyWriteFailureWithoutPreviousCertLeavesNoCert(t *testing.T) {
	e := newHostConflictEnv(t, []config.Domain{{Host: "site.test", Type: "static"}})
	dir := t.TempDir()
	certUploadDir = dir
	t.Cleanup(func() { certUploadDir = "/var/lib/uwas/certs" })

	hostDir := filepath.Join(dir, "site.test")
	if err := os.MkdirAll(filepath.Join(hostDir, "key.pem", "block"), 0o700); err != nil {
		t.Fatal(err)
	}
	cert, key := selfSignedPair(t, "site.test")
	b, _ := json.Marshal(map[string]string{"cert": cert, "key": key})
	if code := e.do(http.MethodPost, "/api/v1/certs/site.test/upload", string(b), auth.RoleAdmin); code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", code)
	}
	if _, err := os.Stat(filepath.Join(hostDir, "cert.pem")); !os.IsNotExist(err) {
		t.Fatalf("orphan cert.pem left behind (err=%v)", err)
	}
}
