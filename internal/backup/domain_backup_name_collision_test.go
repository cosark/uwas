package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F3500: two domain backups of the same domain within one second share a
// filename; the second silently replaces the first.
func TestCreateDomainBackupSameSecondKeepsBoth(t *testing.T) {
	webRoot := t.TempDir()
	dest := t.TempDir()
	m := New(config.BackupConfig{}, logger.New("error", "text"))
	m.providers["local"] = NewLocalProvider(dest)

	var a, b string
	for try := 0; try < 50; try++ {
		for _, e := range globDomainBackups(t, dest) {
			os.Remove(e)
		}
		os.WriteFile(filepath.Join(webRoot, "index.html"), []byte("first"), 0o644)
		s1 := time.Now().Unix()
		i1, err := m.CreateDomainBackup("example.com", webRoot, "", "local")
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(webRoot, "index.html"), []byte("second-version"), 0o644)
		i2, err := m.CreateDomainBackup("example.com", webRoot, "", "local")
		if err != nil {
			t.Fatal(err)
		}
		if time.Now().Unix() == s1 {
			a, b = i1.Name, i2.Name
			break
		}
		time.Sleep(time.Until(time.Unix(s1+1, 0)))
	}
	if a == "" {
		t.Skip("could not get two backups within one second")
	}
	n := len(globDomainBackups(t, dest))
	t.Logf("EXPECTED: 2 distinct archives (names %q vs %q)", a, b)
	t.Logf("ACTUAL: %d archive(s) on disk", n)
	// control: archives for different domains never collide
	i3, _ := m.CreateDomainBackup("other.com", webRoot, "", "local")
	if i3 == nil || strings.Contains(i3.Name, "example.com") {
		t.Fatal("control failed")
	}
	if n != 2 || a == b {
		t.Fatal("same-second domain backups collided")
	}
}

func globDomainBackups(t *testing.T, dir string) []string {
	m, _ := filepath.Glob(filepath.Join(dir, "uwas-domain-example.com-*.tar.gz"))
	return m
}
