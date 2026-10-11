package sftpserver

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openDirHandle(t *testing.T, rt func(byte, []byte) (byte, uint32, []byte), path string) string {
	t.Helper()
	_, _, body := rt(sshFXPOpenDir, marshalString(path))
	if len(body) < 4 {
		t.Fatalf("OPENDIR %q: short reply", path)
	}
	n := binary.BigEndian.Uint32(body[0:4])
	return string(body[4 : 4+n])
}

// F7110: a directory handle kept only its path, so swapping the directory for a
// symlink after OPENDIR made READDIR (run by the server, not the tenant) list a
// directory outside the chroot.
func TestReadDirHandleSurvivesSwappedDirectory(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	outside, _ := filepath.EvalSymlinks(t.TempDir())
	os.Mkdir(filepath.Join(root, "d"), 0o755)
	os.WriteFile(filepath.Join(root, "d", "mine.txt"), nil, 0o644)
	os.WriteFile(filepath.Join(outside, "secret-name.txt"), nil, 0o600)

	rt := pipeSFTP(t, root, false)
	h := openDirHandle(t, rt, "d")
	os.Rename(filepath.Join(root, "d"), filepath.Join(root, "d.old"))
	os.Symlink(outside, filepath.Join(root, "d"))
	_, _, names := rt(sshFXPReadDir, marshalString(h))
	if strings.Contains(string(names), "secret-name.txt") {
		t.Fatal("READDIR listed a directory outside the chroot")
	}
	if !strings.Contains(string(names), "mine.txt") {
		t.Fatalf("READDIR on the opened directory lost its own entries: %q", names)
	}
}

// F7111: FSETSTAT on a directory handle reopened its path, so a swapped parent
// made the server chmod a directory outside the chroot.
func TestFSetStatDirHandleDoesNotFollowSwappedParent(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	outside, _ := filepath.EvalSymlinks(t.TempDir())
	os.MkdirAll(filepath.Join(root, "d", "sub"), 0o755)
	os.MkdirAll(filepath.Join(outside, "sub"), 0o700)

	rt := pipeSFTP(t, root, false)
	h := openDirHandle(t, rt, "d/sub")
	os.Rename(filepath.Join(root, "d"), filepath.Join(root, "d.old"))
	os.Symlink(outside, filepath.Join(root, "d"))
	rt(sshFXPFSetStat, append(marshalString(h), permAttrs(0o777)...))
	if fi, _ := os.Stat(filepath.Join(outside, "sub")); fi.Mode().Perm() != 0o700 {
		t.Fatalf("directory outside the chroot was chmod'ed to %v", fi.Mode().Perm())
	}
}

// F7112: REMOVE/RMDIR/MKDIR acted on the checked path by name; a parent swapped
// for a symlink between safePath and the syscall redirected them outside.
func TestRemoveMkdirDoNotFollowSwappedParent(t *testing.T) {
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

	rmSafe := sess.safePath("d/f")
	mkSafe := sess.safePath("d/newdir")
	if rmSafe == "" || mkSafe == "" {
		t.Fatal("control: paths inside the chroot rejected")
	}
	os.Rename(filepath.Join(root, "d"), filepath.Join(root, "d.old"))
	os.Symlink(outside, filepath.Join(root, "d"))

	if err := sess.removeEntry(rmSafe); err == nil {
		t.Error("removeEntry followed the swapped parent")
	}
	if _, err := os.Stat(filepath.Join(outside, "f")); err != nil {
		t.Errorf("file outside the chroot was removed: %v", err)
	}
	if err := sess.mkdirEntry(mkSafe); err == nil {
		t.Error("mkdirEntry followed the swapped parent")
	}
	if _, err := os.Stat(filepath.Join(outside, "newdir")); err == nil {
		t.Error("directory created outside the chroot")
	}
}

// Control: the same operations work on an unswapped tree.
func TestRemoveMkdirInsideChroot(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	os.Mkdir(filepath.Join(root, "d"), 0o755)
	os.WriteFile(filepath.Join(root, "d", "f"), []byte("x"), 0o644)
	rt := pipeSFTP(t, root, false)
	if _, _, b := rt(sshFXPMkDir, marshalString("d/new")); statusCode(b) != sshFXOK {
		t.Fatalf("mkdir status %d", statusCode(b))
	}
	if _, _, b := rt(sshFXPRemove, marshalString("d/f")); statusCode(b) != sshFXOK {
		t.Fatalf("remove status %d", statusCode(b))
	}
	if _, _, b := rt(sshFXPRmDir, marshalString("d/new")); statusCode(b) != sshFXOK {
		t.Fatalf("rmdir status %d", statusCode(b))
	}
}
