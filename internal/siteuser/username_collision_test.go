package siteuser

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// F11000: dots map to "--", so "shop.example.com" and "shop--example.com" used
// to share one system account. The second tenant could then adopt it (password
// reset, directory re-owned) and delete it together with its authorized_keys.

type collisionEnv struct {
	tmp  string
	cmds []string
}

func newCollisionEnv(t *testing.T, passwdLines ...string) *collisionEnv {
	t.Helper()
	snap := saveHooks()
	t.Cleanup(func() { restoreHooks(snap) })
	runtimeGOOS = "linux"

	e := &collisionEnv{tmp: t.TempDir()}
	passwd := filepath.Join(e.tmp, "passwd")
	if err := os.WriteFile(passwd, []byte(strings.Join(passwdLines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	passwdPath = passwd
	sshd := filepath.Join(e.tmp, "sshd_config")
	if err := os.WriteFile(sshd, []byte("Subsystem sftp internal-sftp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sshdConfigPath = sshd
	execCommandFn = func(name string, args ...string) *exec.Cmd {
		e.cmds = append(e.cmds, name+" "+strings.Join(args, " "))
		if name == "useradd" {
			return fakeExecCommandUseraddFails(name, args...) // account already exists
		}
		return fakeExecCommand(name, args...)
	}
	return e
}

func (e *collisionEnv) ran(cmd string) bool {
	for _, c := range e.cmds {
		if c == cmd {
			return true
		}
	}
	return false
}

func passwdLine(user, home string) string {
	return fmt.Sprintf("%s:x:1001:33::%s:/usr/sbin/nologin", user, home)
}

func TestDomainToUsernameDistinguishesDashedHosts(t *testing.T) {
	if got := domainToUsername("example.com"); got != "uwas-example--com" {
		t.Errorf("plain host name changed: %q", got)
	}
	a, b := domainToUsername("shop.example.com"), domainToUsername("shop--example.com")
	if a == b {
		t.Fatalf("shop.example.com and shop--example.com share account %q", a)
	}
	for _, h := range []string{"shop--example.com", "SHOP--Example.COM", "a--b", "x--y--z.org", "averyveryverylonghostname--example.com"} {
		n := domainToUsername(h)
		if len(n) > 32 || !strings.HasPrefix(n, "uwas-") {
			t.Errorf("%q -> %q: want <=32 chars with uwas- prefix", h, n)
		}
	}
	if domainToUsername("Shop--Example.com") != domainToUsername("shop--example.com") {
		t.Error("hostname case must not change the account")
	}
}

func TestCreateUserDoesNotAdoptAnotherHostsAccount(t *testing.T) {
	victimHome := "/srv/www/shop.example.com"
	e := newCollisionEnv(t, passwdLine(legacyUsername("shop--example.com"), victimHome))

	// The dashed spelling collides with the victim's legacy account name.
	web := filepath.Join(e.tmp, "shop--example.com", "public_html")
	u, _, err := CreateUserForWebDir(web, "shop--example.com")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.Username == legacyUsername("shop--example.com") {
		t.Fatalf("adopted the other host's account %q", u.Username)
	}

	// Even if the names did collide, an account recorded for a different
	// directory must be refused rather than reset.
	host := "x.example.com"
	e2 := newCollisionEnv(t, passwdLine(domainToUsername(host), "/srv/www/other.org"))
	if _, _, err := CreateUserForWebDir(filepath.Join(e2.tmp, host, "public_html"), host); err == nil {
		t.Fatal("adopted an account whose home belongs to another directory")
	}

	// Control: re-creating the host's own account (same directory name) still works.
	own := filepath.Join(t.TempDir(), host, "public_html")
	e3 := newCollisionEnv(t, passwdLine(domainToUsername(host), filepath.Dir(own)))
	if _, _, err := CreateUserForWebDir(own, host); err != nil {
		t.Fatalf("re-create of the host's own account: %v", err)
	}
	_ = e3
}

func TestDeleteUserLeavesCollidingHostsAccountAlone(t *testing.T) {
	tmp := t.TempDir()
	victimHome := filepath.Join(tmp, "shop.example.com")
	if err := os.MkdirAll(filepath.Join(victimHome, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(victimHome, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("ssh-ed25519 AAAA victim\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	victimAcct := legacyUsername("shop.example.com")
	e := newCollisionEnv(t, passwdLine(victimAcct, victimHome))

	if err := DeleteUser("shop--example.com"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if e.ran("userdel " + victimAcct) {
		t.Error("deleting shop--example.com removed shop.example.com's account")
	}
	if _, err := os.Stat(keys); err != nil {
		t.Errorf("victim authorized_keys gone: %v", err)
	}

	// Control: the owner can still delete its own account and keys.
	if err := DeleteUser("shop.example.com"); err != nil {
		t.Fatalf("delete own: %v", err)
	}
	if !e.ran("userdel " + victimAcct) {
		t.Error("owner's DeleteUser did not run userdel")
	}
	if _, err := os.Stat(keys); !os.IsNotExist(err) {
		t.Errorf("owner's authorized_keys not removed: %v", err)
	}
}

func TestLegacyAccountOfDashedHostIsStillRecognised(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "shop--example.com")
	legacy := legacyUsername("shop--example.com")
	e := newCollisionEnv(t, passwdLine(legacy, home))

	if got := accountName("shop--example.com", ""); got != legacy {
		t.Fatalf("account for the dashed host's own legacy account = %q, want %q", got, legacy)
	}
	if err := DeleteUser("shop--example.com"); err != nil {
		t.Fatal(err)
	}
	if !e.ran("userdel " + legacy) {
		t.Error("legacy account of the dashed host was orphaned")
	}
}
