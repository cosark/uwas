package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func f21801Archive(t *testing.T, path string, entries [][2]string) {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e[0], Size: int64(len(e[1])), Mode: 0o644, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func f21801Read(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return "<missing>"
	}
	return string(b)
}

func f21801Leftovers(t *testing.T, dirs ...string) []string {
	t.Helper()
	var left []string
	for _, d := range dirs {
		_ = filepath.Walk(d, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && filepath.Ext(p) == ".uwas-restore" {
				left = append(left, p)
			}
			return nil
		})
	}
	return left
}

func TestRestoreDuplicateArchiveMember(t *testing.T) {
	base := t.TempDir()
	run := func(name string, entries [][2]string) (cfg, certs string, err error) {
		arc := filepath.Join(base, name+".tar.gz")
		f21801Archive(t, arc, entries)
		cfg, certs = filepath.Join(base, name+"-cfg"), filepath.Join(base, name+"-certs")
		err = restoreBackup(arc, cfg, certs)
		return
	}

	// Reproduction: duplicate member, later member must survive, last copy wins.
	cfg, certs, err := run("dup", [][2]string{{"config/a.yaml", "one"}, {"config/a.yaml", "two"}, {"config/b.yaml", "bee"}})
	if err != nil || f21801Read(filepath.Join(cfg, "a.yaml")) != "two" || f21801Read(filepath.Join(cfg, "b.yaml")) != "bee" {
		t.Fatalf("EXPECTED err=nil a=two b=bee, ACTUAL err=%v a=%s b=%s", err,
			f21801Read(filepath.Join(cfg, "a.yaml")), f21801Read(filepath.Join(cfg, "b.yaml")))
	}
	if l := f21801Leftovers(t, cfg, certs); len(l) != 0 {
		t.Fatalf("leftover temp files: %v", l)
	}

	// Edge: three copies plus a later member and an earlier member.
	cfg, _, err = run("triple", [][2]string{
		{"config/z.yaml", "zed"}, {"config/a.yaml", "1"}, {"config/a.yaml", "2"}, {"config/a.yaml", "3"}, {"config/b.yaml", "bee"},
	})
	if err != nil || f21801Read(filepath.Join(cfg, "a.yaml")) != "3" ||
		f21801Read(filepath.Join(cfg, "z.yaml")) != "zed" || f21801Read(filepath.Join(cfg, "b.yaml")) != "bee" {
		t.Fatalf("triple duplicate: err=%v", err)
	}

	// Edge: differently spelled names that clean to the same destination.
	cfg, _, err = run("spell", [][2]string{{"config/a.yaml", "old"}, {"config//a.yaml", "mid"}, {"config/./a.yaml", "new"}, {"config/b.yaml", "bee"}})
	if err != nil || f21801Read(filepath.Join(cfg, "a.yaml")) != "new" || f21801Read(filepath.Join(cfg, "b.yaml")) != "bee" {
		t.Fatalf("spelling variants: err=%v a=%s", err, f21801Read(filepath.Join(cfg, "a.yaml")))
	}

	// Edge: duplicate under certs/ and mixed with config/.
	cfg, certs, err = run("certs", [][2]string{{"certs/k.pem", "k1"}, {"config/c.yaml", "c"}, {"certs/k.pem", "k2"}})
	if err != nil || f21801Read(filepath.Join(certs, "k.pem")) != "k2" || f21801Read(filepath.Join(cfg, "c.yaml")) != "c" {
		t.Fatalf("certs duplicate: err=%v", err)
	}

	// Edge: truncated archive after a duplicate installs nothing and leaves no temp.
	arc := filepath.Join(base, "trunc.tar.gz")
	f21801Archive(t, arc, [][2]string{{"config/a.yaml", "one"}, {"config/a.yaml", "two"}})
	raw, _ := os.ReadFile(arc)
	if err := os.WriteFile(arc, raw[:len(raw)-8], 0o600); err != nil {
		t.Fatal(err)
	}
	tcfg, tcerts := filepath.Join(base, "trunc-cfg"), filepath.Join(base, "trunc-certs")
	if err := restoreBackup(arc, tcfg, tcerts); err == nil {
		t.Fatal("truncated archive must fail")
	}
	if f21801Read(filepath.Join(tcfg, "a.yaml")) != "<missing>" {
		t.Fatal("truncated archive installed a file")
	}
	if l := f21801Leftovers(t, tcfg, tcerts); len(l) != 0 {
		t.Fatalf("leftover temp files after failure: %v", l)
	}

}
