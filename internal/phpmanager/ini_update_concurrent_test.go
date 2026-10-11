package phpmanager

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// F8510: updateINI was an unlocked read-modify-write, so two concurrent
// SetConfig calls for different keys lost one update, and the in-place
// truncating write let FPM read a partial php.ini.
func TestUpdateINIConcurrentUpdatesKeepBothKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "php.ini")
	os.WriteFile(path, []byte("memory_limit = 128M\n"), 0o644)

	readDone := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	afterINIRead = func() {
		first := false
		once.Do(func() { first = true })
		if first {
			close(readDone)
			<-release
		}
	}
	defer func() { afterINIRead = nil }()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); updateINI(path, "upload_max_filesize", "64M") }()
	<-readDone

	bDone := make(chan struct{})
	go func() { updateINI(path, "post_max_size", "64M"); close(bDone) }()
	select {
	case <-bDone: // unserialized: the second update finished while the first was paused
	case <-time.After(300 * time.Millisecond): // serialized behind the first
	}
	close(release)
	wg.Wait()
	<-bDone

	b, _ := os.ReadFile(path)
	got := string(b)
	for _, want := range []string{"memory_limit = 128M", "upload_max_filesize = 64M", "post_max_size = 64M"} {
		if !strings.Contains(got, want) {
			t.Errorf("php.ini lost %q:\n%s", want, got)
		}
	}
}

func TestUpdateINIKeepsModeSymlinkAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.ini")
	link := filepath.Join(dir, "php.ini")
	os.WriteFile(real, []byte("memory_limit = 128M\n"), 0o600)
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}

	if err := updateINI(link, "memory_limit", "256M"); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("php.ini symlink was replaced by a regular file: %v %v", fi, err)
	}
	fi, err := os.Stat(real)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v (%v), want 0600 preserved", fi.Mode().Perm(), err)
	}
	if b, _ := os.ReadFile(real); !strings.Contains(string(b), "memory_limit = 256M") {
		t.Errorf("target not updated: %q", b)
	}
	if err := writeINIAtomic(link, []byte("a = 1\n")); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}
