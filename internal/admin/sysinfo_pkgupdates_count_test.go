package admin

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeAptOnPath puts an `apt` that prints the given lines first on PATH, so
// refreshSysInfoCache's `apt list --upgradable` pipeline runs against a known
// listing instead of the host's package state.
func fakeAptOnPath(t *testing.T, listing string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\ncat <<'EOF'\n" + listing + "EOF\n"
	if err := os.WriteFile(filepath.Join(dir, "apt"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func pkgUpdatesAfterRefresh(t *testing.T) string {
	t.Helper()
	s := testServer()
	s.sysInfoRefreshing.Store(true)
	s.refreshSysInfoCache("")
	s.sysInfoCacheMu.Lock()
	defer s.sysInfoCacheMu.Unlock()
	return s.sysInfoPkgUpdates
}

// With nothing upgradable `grep -c` prints 0 and exits 1; the `|| echo 0`
// fallback then printed a second 0, so package_updates was "0\n0".
func TestSysInfoPackageUpdatesCountIsASingleNumberWhenNoUpdates(t *testing.T) {
	fakeAptOnPath(t, "Listing...\n")
	if got := pkgUpdatesAfterRefresh(t); got != "0" {
		t.Fatalf("EXPECTED: %q\nACTUAL: %q", "0", got)
	}
}

// Control: with upgradable packages the count is a single number.
func TestSysInfoPackageUpdatesCountWithUpdates(t *testing.T) {
	fakeAptOnPath(t, "Listing...\na/stable 2 amd64 [upgradable from: 1]\nb/stable 3 amd64 [upgradable from: 2]\n")
	if got := pkgUpdatesAfterRefresh(t); got != "2" {
		t.Fatalf("package_updates = %q, want %q", got, "2")
	}
}

// Edge: a single upgradable package, and the same refresh repeated.
func TestSysInfoPackageUpdatesCountSingleAndRepeated(t *testing.T) {
	fakeAptOnPath(t, "Listing...\na/stable 2 amd64 [upgradable from: 1]\n")
	for i := 0; i < 2; i++ {
		if got := pkgUpdatesAfterRefresh(t); got != "1" {
			t.Fatalf("run %d: package_updates = %q, want %q", i, got, "1")
		}
	}
}
