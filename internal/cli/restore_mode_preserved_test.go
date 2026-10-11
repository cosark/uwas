package cli

import (
	"archive/tar"
	"os"
	"path/filepath"
	"testing"
)

// F8300: restoring over a live file keeps the live file's permissions; a new
// file takes the archive's mode capped at rwxr-xr-x.
func TestRestoreKeepsLiveFileMode(t *testing.T) {
	cases := []struct {
		name        string
		live        os.FileMode // 0 = file does not exist yet
		archiveMode int64
		want        os.FileMode
	}{
		{"hardened live file, archive recorded 0644", 0o600, 0o644, 0o600},
		{"live file stricter than archive", 0o640, 0o666, 0o640},
		{"live mode kept exactly, independent of umask", 0o664, 0o600, 0o664},
		{"agreeing modes", 0o600, 0o600, 0o600},
		{"new file takes archive mode", 0, 0o640, 0o640},
		{"new file never world writable", 0, 0o666, 0o644},
		{"new file drops setuid bits", 0, 0o4755, 0o755},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgDir, certDir := filepath.Join(dir, "etc"), filepath.Join(dir, "certs")
			os.MkdirAll(cfgDir, 0o755)
			os.MkdirAll(certDir, 0o755)
			live := filepath.Join(cfgDir, "uwas.yaml")
			if c.live != 0 {
				os.WriteFile(live, []byte("LIVE"), 0o600)
				os.Chmod(live, c.live)
			}
			arc := stagedRestoreArchive(t,
				[]tar.Header{{Name: "config/uwas.yaml", Mode: c.archiveMode, Typeflag: tar.TypeReg}},
				[][]byte{[]byte("NEW")})
			in := filepath.Join(dir, "b.tar.gz")
			os.WriteFile(in, arc, 0o600)
			if err := (&RestoreCommand{}).Run([]string{"--input", in, "--config-dir", cfgDir, "--certs-dir", certDir}); err != nil {
				t.Fatal(err)
			}
			st, err := os.Stat(live)
			if err != nil {
				t.Fatal(err)
			}
			if st.Mode().Perm() != c.want || st.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
				t.Errorf("mode = %v, want %v", st.Mode(), c.want)
			}
			if b, _ := os.ReadFile(live); string(b) != "NEW" {
				t.Errorf("content = %q, want NEW", b)
			}
		})
	}
}
