package database

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeDockerUsersServer installs a `docker` on PATH that answers `inspect` with a
// MariaDB image and records every SQL batch fed to `exec`. A batch asking about
// mysql.user answers "1" for the accounts in existing, "0" otherwise. With
// failLookup it exits 1 for that batch.
func fakeDockerUsersServer(t *testing.T, failLookup bool, existing ...string) (logPath string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell fake docker")
	}
	dir := t.TempDir()
	logPath = filepath.Join(dir, "sql.log")
	var cases strings.Builder
	for _, u := range existing {
		cases.WriteString("      *\"User = '" + u + "'\"*) echo 1;;\n")
	}
	lookup := "    case \"$sql\" in\n" + cases.String() + "      *) echo 0;;\n    esac;;\n"
	if failLookup {
		lookup = "    echo 'ERROR 2002: cannot connect' >&2; exit 1;;\n"
	}
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = inspect ]; then echo mariadb:11; exit 0; fi\n" +
		"if [ \"$1\" = exec ]; then\n" +
		"  sql=$(cat)\n" +
		"  printf '%s\\n----\\n' \"$sql\" >> '" + logPath + "'\n" +
		"  case \"$sql\" in\n" +
		"  *'FROM mysql.user'*)\n" + lookup +
		"  esac\n" +
		"  exit 0\n" +
		"fi\n" +
		"exit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

// dockerWriteBatches returns the recorded batches that create or grant.
func dockerWriteBatches(logPath string) []string {
	b, _ := os.ReadFile(logPath)
	var w []string
	for _, batch := range strings.Split(string(b), "\n----\n") {
		if strings.Contains(batch, "CREATE USER") || strings.Contains(batch, "GRANT") {
			w = append(w, batch)
		}
	}
	return w
}

// F21701: CREATE USER IF NOT EXISTS is a no-op for an existing account, so the
// password DockerDBCreateDatabase returned was never set while the account
// (possibly another site's) was granted on the new database.
func TestDockerDBCreateDatabaseRefusesExistingUser(t *testing.T) {
	logPath := fakeDockerUsersServer(t, false, "siteb")

	// control: a fresh account is created and granted
	if _, err := DockerDBCreateDatabase("uwas-db-x", "sitea", "sitea", "pw-a"); err != nil {
		t.Fatalf("control: %v", err)
	}
	if w := dockerWriteBatches(logPath); len(w) != 1 || !strings.Contains(w[0], "GRANT") {
		t.Fatalf("control: expected one grant batch, got %q", w)
	}

	if err := os.Remove(logPath); err != nil {
		t.Fatal(err)
	}
	res, err := DockerDBCreateDatabase("uwas-db-x", "sitea2", "siteb", "pw-new")
	if err == nil {
		t.Fatalf("existing account silently reused, returned password %q", res.Password)
	}
	if !errors.Is(err, ErrUserExists) {
		t.Errorf("err = %v, want ErrUserExists", err)
	}
	if w := dockerWriteBatches(logPath); len(w) != 0 {
		t.Errorf("statements ran despite the refusal: %q", w)
	}
}

// A failed account lookup must stop the creation rather than guess "absent".
func TestDockerDBCreateDatabaseLookupFailureAborts(t *testing.T) {
	logPath := fakeDockerUsersServer(t, true)
	if _, err := DockerDBCreateDatabase("uwas-db-x", "sitea", "sitea", "pw-a"); err == nil {
		t.Fatal("create succeeded although the account lookup failed")
	}
	if w := dockerWriteBatches(logPath); len(w) != 0 {
		t.Errorf("statements ran after a failed lookup: %q", w)
	}
}

// The lookup quotes the account name like every other literal.
func TestDockerDBCreateDatabaseLookupIsValidated(t *testing.T) {
	logPath := fakeDockerUsersServer(t, false)
	if _, err := DockerDBCreateDatabase("uwas-db-x", "sitea", "a'b", "pw"); err == nil {
		t.Fatal("invalid user accepted")
	}
	if b, _ := os.ReadFile(logPath); len(b) != 0 {
		t.Errorf("SQL ran for an invalid user: %q", b)
	}
}
