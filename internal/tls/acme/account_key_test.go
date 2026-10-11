package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/logger"
)

func writeAccountKey(t *testing.T, dir string, block *pem.Block, trim int) string {
	t.Helper()
	p := filepath.Join(dir, "account.key")
	data := pem.EncodeToMemory(block)
	if trim > 0 {
		data = data[:len(data)/trim]
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func asideFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "account.key.unusable-") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

func newTestAccountClient(dir string) *Client {
	return NewClient("https://x.invalid/dir", dir, logger.New("error", "text"))
}

// F15402: a valid account key in the PKCS#8 form openssl and certbot export is
// the operator's account; it must be reused, never overwritten.
func TestAccountKeyPKCS8IsReusedAndLeftAlone(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	p := writeAccountKey(t, dir, &pem.Block{Type: "PRIVATE KEY", Bytes: der}, 0)
	before, _ := os.ReadFile(p)

	c := newTestAccountClient(dir)
	if err := c.loadOrCreateAccountKey(); err != nil {
		t.Fatal(err)
	}
	if !c.accountKey.Equal(key) {
		t.Fatal("the PKCS#8 account key was not reused")
	}
	after, _ := os.ReadFile(p)
	if string(after) != string(before) || len(asideFiles(t, dir)) != 0 {
		t.Fatal("a reusable account key was rewritten or set aside")
	}
}

// An unusable key (truncated, or a curve ES256 cannot sign with) is set aside,
// not destroyed, and a fresh key is written atomically with mode 0600.
func TestUnusableAccountKeyIsSetAsideNotOverwritten(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sec1, _ := x509.MarshalECPrivateKey(key)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384der, _ := x509.MarshalECPrivateKey(p384)

	cases := []struct {
		name  string
		block *pem.Block
		trim  int
	}{
		{"truncated", &pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}, 2},
		{"P-384", &pem.Block{Type: "EC PRIVATE KEY", Bytes: p384der}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := writeAccountKey(t, dir, tc.block, tc.trim)
			original, _ := os.ReadFile(p)

			c := newTestAccountClient(dir)
			if err := c.loadOrCreateAccountKey(); err != nil {
				t.Fatal(err)
			}
			aside := asideFiles(t, dir)
			if len(aside) != 1 {
				t.Fatalf("expected the old key set aside, found %v", aside)
			}
			if kept, _ := os.ReadFile(aside[0]); string(kept) != string(original) {
				t.Fatal("the set-aside copy differs from the original key")
			}
			fresh, _ := os.ReadFile(p)
			if parseAccountKey(fresh) == nil {
				t.Fatal("the replacement account.key is not a usable key")
			}
			if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
				t.Fatalf("account.key mode = %v, want 0600", fi.Mode().Perm())
			}
			if c.accountKey == nil || c.accountKey.Equal(key) {
				t.Fatal("expected a newly generated account key")
			}
		})
	}
}

func TestFirstAccountKeyIsWrittenWithoutLeftovers(t *testing.T) {
	dir := t.TempDir()
	c := newTestAccountClient(dir)
	if err := c.loadOrCreateAccountKey(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "account.key" {
		t.Fatalf("storage dir holds %v, want only account.key", entries)
	}
	// A second client reads the same key back.
	c2 := newTestAccountClient(dir)
	if err := c2.loadOrCreateAccountKey(); err != nil || !c2.accountKey.Equal(c.accountKey) {
		t.Fatalf("persisted key not reloaded: %v", err)
	}
}
