//go:build linux

package siteuser

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// F6200: the root-run chown that follows an authorized_keys write must act on
// the file itself. The tenant owns the .ssh directory, so it can swap the file
// for a symlink between the write and the chown; without -h root would hand
// the link's target to the tenant. Real chown is used, with the owner argument
// rewritten to a supplementary group of the test user so it runs unprivileged.
func TestChownDoesNotFollowSwappedAuthorizedKeys(t *testing.T) {
	own := os.Getgid()
	other := -1
	groups, _ := os.Getgroups()
	for _, g := range groups {
		if g != own {
			other = g
			break
		}
	}
	if other < 0 {
		t.Skip("test user has no supplementary group to chown to")
	}
	if _, err := exec.LookPath("chown"); err != nil {
		t.Skip("no chown binary")
	}
	snap := saveHooks()
	defer restoreHooks(snap)
	runtimeGOOS = "linux"
	osMkdirAllFn = os.MkdirAll
	osReadFileFn = os.ReadFile
	osOpenFileFn = os.OpenFile

	const pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UiqLqrZsfZdYvbZyVDkjPOAyMyGu x"
	gidOf := func(p string) int {
		var st syscall.Stat_t
		if err := syscall.Lstat(p, &st); err != nil {
			t.Fatal(err)
		}
		return int(st.Gid)
	}
	run := func(swap bool) (victim, keys int) {
		root := t.TempDir()
		webDir := filepath.Join(root, "dom", "public_html")
		os.MkdirAll(webDir, 0o755)
		victimPath := filepath.Join(root, "victim")
		os.WriteFile(victimPath, []byte("root-only"), 0o600)
		keysPath := filepath.Join(root, "dom", ".ssh", "authorized_keys")
		swapped := false
		execCommandFn = func(name string, args ...string) *exec.Cmd {
			if name != "chown" {
				return exec.Command("true")
			}
			path := args[len(args)-1]
			if swap && strings.HasSuffix(path, "authorized_keys") && !swapped {
				swapped = true
				os.Remove(keysPath)
				os.Symlink(victimPath, keysPath)
			}
			na := append([]string(nil), args...)
			for i, a := range na {
				if strings.Contains(a, ":") && !strings.HasPrefix(a, "-") {
					na[i] = ":" + strconv.Itoa(other)
				}
			}
			return exec.Command("chown", na...)
		}
		if err := AddSSHKeyForWebDir(webDir, "example.com", pub); err != nil {
			t.Fatalf("add key: %v", err)
		}
		return gidOf(victimPath), gidOf(keysPath)
	}

	if v, k := run(false); v != own || k != other {
		t.Fatalf("control: victim gid %d (want %d), keys gid %d (want %d)", v, own, k, other)
	}
	if v, _ := run(true); v != own {
		t.Errorf("chown followed the swapped symlink: outside file gid %d, want %d", v, own)
	}
}
