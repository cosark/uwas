package cronjob

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestRemoveByDomainIgnoresQuotedMarkerInComment(t *testing.T) {
	origExec, origGOOS := execCommandFn, runtimeGOOS
	defer func() { execCommandFn = origExec; runtimeGOOS = origGOOS }()
	runtimeGOOS = "linux"
	crontab := strings.Join([]string{
		"# UWAS managed [a.com] mine",
		"0 2 * * * /bin/a",
		"# UWAS managed [b.com] see # UWAS managed [a.com] note",
		"0 3 * * * /bin/b",
		"",
	}, "\n")
	var written string
	execCommandFn = func(name string, args ...string) *exec.Cmd {
		if len(args) == 1 && args[0] == "-l" {
			return exec.Command("echo", crontab)
		}
		if len(args) == 1 {
			d, _ := os.ReadFile(args[0])
			written = string(d)
		}
		return exec.Command("true")
	}
	if err := RemoveByDomain("a.com"); err != nil {
		t.Fatal(err)
	}
	ctrl := !strings.Contains(written, "/bin/a")
	bKept := strings.Contains(written, "/bin/b")

	if !ctrl {
		t.Fatal("a.com job not removed")
	}
	if !bKept {
		t.Fatalf("another domain's job was removed: %q", written)
	}
}
