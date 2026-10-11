package admin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/auth"
	"github.com/uwaserver/uwas/internal/config"
)

func selfSignedPair(t *testing.T, host string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}

// F12500: a certificate upload replaces the working pair on disk and flips the
// domain to manual TLS, so a pair that does not parse or does not match must be
// refused before anything is written.
func TestCertUploadRefusesUnusablePairs(t *testing.T) {
	e := newHostConflictEnv(t, []config.Domain{{Host: "site.test", Type: "static"}})
	dir := t.TempDir()
	certUploadDir = dir
	t.Cleanup(func() { certUploadDir = "/var/lib/uwas/certs" })

	hostDir := filepath.Join(dir, "site.test")
	if err := os.MkdirAll(hostDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"cert.pem": "WORKING-CERT", "key.pem": "WORKING-KEY"} {
		if err := os.WriteFile(filepath.Join(hostDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cert, key := selfSignedPair(t, "site.test")
	_, otherKey := selfSignedPair(t, "other.test")
	upload := func(c, k string) int {
		b, _ := json.Marshal(map[string]string{"cert": c, "key": k})
		return e.do(http.MethodPost, "/api/v1/certs/site.test/upload", string(b), auth.RoleAdmin)
	}
	untouched := func(label string) {
		t.Helper()
		got, _ := os.ReadFile(filepath.Join(hostDir, "cert.pem"))
		if string(got) != "WORKING-CERT" {
			t.Errorf("%s: working certificate was overwritten with %q", label, got)
		}
		e.s.configMu.RLock()
		mode := e.s.config.Domains[0].SSL.Mode
		e.s.configMu.RUnlock()
		if mode != "off" {
			t.Errorf("%s: ssl.mode switched to %q", label, mode)
		}
	}

	if code := upload("junk", "junk"); code != http.StatusBadRequest {
		t.Errorf("junk: status = %d, want 400", code)
	}
	untouched("junk")
	if code := upload(cert, otherKey); code != http.StatusBadRequest {
		t.Errorf("mismatched key: status = %d, want 400", code)
	}
	untouched("mismatched key")

	// A real pair goes through and is installed.
	if code := upload(cert, key); code != http.StatusOK {
		t.Fatalf("valid pair: status = %d, want 200", code)
	}
	got, _ := os.ReadFile(filepath.Join(hostDir, "cert.pem"))
	if string(got) != cert {
		t.Error("valid pair was not installed")
	}
	e.s.configMu.RLock()
	mode := e.s.config.Domains[0].SSL.Mode
	e.s.configMu.RUnlock()
	if mode != "manual" {
		t.Errorf("valid pair: ssl.mode = %q, want manual", mode)
	}
}
