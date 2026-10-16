package cli

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func f21802Members(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gr)
	out := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("archive unreadable: %v", err)
		}
		b, _ := io.ReadAll(tr)
		out[h.Name] = string(b)
	}
	return out
}

func TestBackupSkipsNonRegularMembers(t *testing.T) {
	base := t.TempDir()
	cfgDir := filepath.Join(base, "etc")
	certs := filepath.Join(base, "certs")
	for _, d := range []string{filepath.Join(cfgDir, "domains.d"), filepath.Join(certs, "real")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	w := func(p, c string) {
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(cfgDir, "uwas.yaml")
	w(cfg, "global: {}\n")
	w(filepath.Join(cfgDir, "domains.d", "ok.yaml"), "host: ok\n")
	w(filepath.Join(certs, "a.pem"), "A")
	w(filepath.Join(certs, "real", "k.pem"), "K")
	w(filepath.Join(certs, "z.pem"), "Z")
	link := func(target, name string) {
		if err := os.Symlink(target, name); err != nil {
			t.Skipf("symlink unsupported: %v", err)
		}
	}
	link(filepath.Join(certs, "real"), filepath.Join(certs, "live"))            // dir symlink
	link(filepath.Join(certs, "z.pem"), filepath.Join(certs, "z-link.pem"))     // file symlink
	link(filepath.Join(certs, "nowhere"), filepath.Join(certs, "dangling.pem")) // broken symlink
	link(filepath.Join(certs, "real"), filepath.Join(cfgDir, "domains.d", "dirlink.yaml"))

	out := filepath.Join(base, "out.tar.gz")
	if err := createBackup(out, cfg, certs); err != nil {
		t.Fatalf("EXPECTED err=nil, ACTUAL %v", err)
	}
	m := f21802Members(t, out)
	want := map[string]string{
		"config/uwas.yaml":         "global: {}\n",
		"config/domains.d/ok.yaml": "host: ok\n",
		"certs/a.pem":              "A",
		"certs/real/k.pem":         "K",
		"certs/z.pem":              "Z",
		"certs/z-link.pem":         "Z", // file symlink still followed
	}
	for k, v := range want {
		if got, ok := m[k]; !ok || got != v {
			t.Fatalf("member %s = %q (present=%v), want %q; all=%v", k, got, ok, v, m)
		}
	}
	for _, bad := range []string{"certs/live", "certs/dangling.pem", "config/domains.d/dirlink.yaml"} {
		if _, ok := m[bad]; ok {
			t.Fatalf("non-regular %s must be skipped", bad)
		}
	}

	// Edge: backup is repeatable and the archive restores end to end.
	out2 := filepath.Join(base, "out2.tar.gz")
	if err := createBackup(out2, cfg, certs); err != nil {
		t.Fatalf("second backup: %v", err)
	}
	rc, rk := filepath.Join(base, "rc"), filepath.Join(base, "rk")
	if err := restoreBackup(out2, rc, rk); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(rk, "real", "k.pem")); string(b) != "K" {
		t.Fatalf("restored key = %q", b)
	}

	// Edge: a config path that is a directory fails cleanly before any header.
	if err := createBackup(filepath.Join(base, "bad.tar.gz"), cfgDir, certs); err == nil {
		t.Fatal("directory as config must be an error")
	}
}
