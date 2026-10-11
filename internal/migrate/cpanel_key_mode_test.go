package migrate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestImportCPanelBackupKeyOwnerOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "backup.tar.gz")
	target := t.TempDir()
	writeCPanelBackup(t, p, map[string]string{
		"cpmove-alice/":                           "",
		"cpmove-alice/homedir/":                   "",
		"cpmove-alice/homedir/public_html/":       "",
		"cpmove-alice/homedir/public_html/i.html": "<html></html>",
		"cpmove-alice/userdata/main":              "main_domain: alice.com\n",
		"cpmove-alice/ssl/alice.com.crt":          "CERTDATA",
		"cpmove-alice/ssl/alice.com.key":          "KEYDATA",
	})
	// operator pre-created .certs world-readable (MkdirAll won't tighten it)
	if err := os.MkdirAll(filepath.Join(target, ".certs"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportCPanelBackup(p, target, false); err != nil {
		t.Fatal(err)
	}
	// control: cert may be 0644
	_, err := os.Stat(filepath.Join(target, ".certs", "alice.com", "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ki, err := os.Stat(filepath.Join(target, ".certs", "alice.com", "key.pem"))
	if err != nil {
		t.Fatal(err)
	}

	if ki.Mode().Perm()&0o077 != 0 {
		t.Fatalf("key.pem mode %v, want 0600", ki.Mode().Perm())
	}
}
