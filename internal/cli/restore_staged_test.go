package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func stagedRestoreArchive(t *testing.T, entries []tar.Header, bodies [][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for i := range entries {
		h := entries[i]
		h.Size = int64(len(bodies[i]))
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		tw.Write(bodies[i])
	}
	tw.Close()
	gw.Close()
	return buf.Bytes()
}

func stagedRestoreRun(t *testing.T, archive []byte) (cfgDir, certDir string, err error) {
	t.Helper()
	dir := t.TempDir()
	cfgDir, certDir = filepath.Join(dir, "etc"), filepath.Join(dir, "certs")
	os.MkdirAll(cfgDir, 0o755)
	os.MkdirAll(certDir, 0o755)
	os.WriteFile(filepath.Join(cfgDir, "uwas.yaml"), []byte("LIVE-CONFIG"), 0o600)
	in := filepath.Join(dir, "b.tar.gz")
	os.WriteFile(in, archive, 0o600)
	err = (&RestoreCommand{}).Run([]string{"--input", in, "--config-dir", cfgDir, "--certs-dir", certDir})
	return cfgDir, certDir, err
}

// F8010: a truncated or corrupt backup must not overwrite the live config or
// leave staged files behind; an intact one restores everything with its mode.
func TestRestoreCorruptArchiveKeepsLiveFiles(t *testing.T) {
	payload := make([]byte, 300<<10)
	rand.Read(payload) // incompressible, so cutting the gzip cuts the entry
	entries := []tar.Header{
		{Name: "config/uwas.yaml", Mode: 0o600, Typeflag: tar.TypeReg},
		{Name: "certs/key.pem", Mode: 0o600, Typeflag: tar.TypeReg},
	}
	full := stagedRestoreArchive(t, entries, [][]byte{payload, []byte("KEY")})

	cfgDir, certDir, err := stagedRestoreRun(t, full)
	if err != nil {
		t.Fatalf("intact archive: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(cfgDir, "uwas.yaml")); !bytes.Equal(b, payload) {
		t.Errorf("intact archive: config not restored (%d bytes)", len(b))
	}
	if st, err := os.Stat(filepath.Join(certDir, "key.pem")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("intact archive: key.pem = %v, %v; want mode 0600", st, err)
	}

	// Cut inside the first entry, and again inside the second one.
	for _, cut := range []int{len(full) / 2, len(full) - 12} {
		cfgDir, certDir, err := stagedRestoreRun(t, full[:cut])
		if err == nil {
			t.Fatalf("cut at %d: truncated archive restored without error", cut)
		}
		if b, _ := os.ReadFile(filepath.Join(cfgDir, "uwas.yaml")); string(b) != "LIVE-CONFIG" {
			t.Errorf("cut at %d: live config overwritten (%d bytes)", cut, len(b))
		}
		for _, d := range []string{cfgDir, certDir} {
			left, _ := filepath.Glob(filepath.Join(d, "*.uwas-restore"))
			if len(left) != 0 {
				t.Errorf("cut at %d: staged files left behind: %v", cut, left)
			}
		}
		if _, err := os.Stat(filepath.Join(certDir, "key.pem")); err == nil {
			t.Errorf("cut at %d: partial archive installed key.pem", cut)
		}
	}
}

// Directory and link entries are not regular files and must not be created as
// (truncated) plain files.
func TestRestoreSkipsNonRegularEntries(t *testing.T) {
	entries := []tar.Header{
		{Name: "config/sub/", Mode: 0o755, Typeflag: tar.TypeDir},
		{Name: "config/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		{Name: "config/uwas.yaml", Mode: 0o600, Typeflag: tar.TypeReg},
	}
	arc := stagedRestoreArchive(t, entries, [][]byte{nil, nil, []byte("NEW")})
	cfgDir, _, err := stagedRestoreRun(t, arc)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(cfgDir, "uwas.yaml")); string(b) != "NEW" {
		t.Errorf("regular entry not restored: %q", b)
	}
	for _, n := range []string{"sub", "link"} {
		if _, err := os.Lstat(filepath.Join(cfgDir, n)); err == nil {
			t.Errorf("non-regular entry %q was created", n)
		}
	}
}
