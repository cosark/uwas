package sftpserver

import (
	"os"
	"path/filepath"
	"testing"
)

// F7401: os.Root refuses a symlink with an absolute target even when it points
// inside the chroot, so after the os.Root migration SFTP paths through a
// deploy's "current -> /home/u/releases/N" failed while the web server and
// safePath accept them.
func TestSFTPPathThroughAbsoluteSymlinkInsideChroot(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	os.MkdirAll(filepath.Join(root, "releases", "1"), 0o755)
	os.WriteFile(filepath.Join(root, "releases", "1", "f.txt"), []byte("x"), 0o644)
	os.Symlink(filepath.Join(root, "releases", "1"), filepath.Join(root, "current")) // absolute
	os.Symlink(filepath.Join("releases", "1"), filepath.Join(root, "rel"))           // relative

	rt := pipeSFTP(t, root, false)
	statOK := func(p string) bool { typ, _, _ := rt(sshFXPStat, marshalString(p)); return typ == sshFXPAttrs }
	dirOK := func(p string) bool { typ, _, _ := rt(sshFXPOpenDir, marshalString(p)); return typ == sshFXPHandle }
	for _, p := range []string{"rel/f.txt", "releases/1/f.txt", "current/f.txt"} {
		if !statOK(p) {
			t.Errorf("STAT %q failed", p)
		}
	}
	for _, p := range []string{"rel", "current"} {
		if !dirOK(p) {
			t.Errorf("OPENDIR %q failed", p)
		}
	}
	if _, _, b := rt(sshFXPRemove, marshalString("current/f.txt")); statusCode(b) != sshFXOK {
		t.Errorf("REMOVE through the absolute symlink: status %d", statusCode(b))
	}
}

// Control: a symlink pointing outside the chroot stays unreachable.
func TestSFTPSymlinkOutsideChrootStillRefused(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	outside, _ := filepath.EvalSymlinks(t.TempDir())
	os.WriteFile(filepath.Join(outside, "secret"), []byte("S"), 0o600)
	os.Symlink(outside, filepath.Join(root, "out"))
	rt := pipeSFTP(t, root, false)
	if typ, _, _ := rt(sshFXPStat, marshalString("out/secret")); typ == sshFXPAttrs {
		t.Error("STAT reached a file outside the chroot")
	}
	if typ, _, _ := rt(sshFXPOpenDir, marshalString("out")); typ == sshFXPHandle {
		t.Error("OPENDIR reached a directory outside the chroot")
	}
}

// The resolved path stays confined by os.Root when a directory is swapped for a
// symlink after the resolution (the F7112 guarantee, kept by F7401's resolver).
func TestSwapAfterResolutionStillConfined(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	outside, _ := filepath.EvalSymlinks(t.TempDir())
	os.Mkdir(filepath.Join(root, "d"), 0o755)
	os.WriteFile(filepath.Join(root, "d", "f"), []byte("mine"), 0o644)
	os.WriteFile(filepath.Join(outside, "f"), []byte("OUTSIDE"), 0o600)
	sess := &sftpSession{root: root, handles: map[string]*openHandle{}}
	t.Cleanup(func() {
		if sess.rh != nil {
			sess.rh.Close()
		}
	})
	safe := sess.safePath("d/f")
	if safe == "" {
		t.Fatal("control: path inside the chroot rejected")
	}
	afterResolve = func() {
		os.Rename(filepath.Join(root, "d"), filepath.Join(root, "d.old"))
		os.Symlink(outside, filepath.Join(root, "d"))
	}
	t.Cleanup(func() { afterResolve = func() {} })
	if err := sess.removeEntry(safe); err == nil {
		t.Error("removeEntry followed the directory swapped after the resolution")
	}
	if _, err := os.Stat(filepath.Join(outside, "f")); err != nil {
		t.Errorf("file outside the chroot was removed: %v", err)
	}
}
