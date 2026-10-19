package cronjob

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

type wsCrontab struct{ state string }

func (g *wsCrontab) command(name string, args ...string) *exec.Cmd {
	if len(args) == 1 && args[0] == "-l" {
		return fakeExecCommand(g.state, 0)(name, args...)
	}
	b, _ := os.ReadFile(args[0])
	g.state = string(b)
	return fakeExecCommand("", 0)(name, args...)
}

// Add must store the spelling List/parseCronLine report: extra spaces in the
// schedule or around the command used to defeat the duplicate check and make
// the job unremovable with the arguments it was added with.
func TestAddRemoveNormalizeWhitespace(t *testing.T) {
	orig := execCommandFn
	defer func() { execCommandFn = orig }()

	t.Run("duplicate with different spacing is rejected", func(t *testing.T) {
		g := &wsCrontab{}
		execCommandFn = g.command
		if err := Add(Job{Schedule: "*/5 * * * *", Command: "/bin/true"}); err != nil {
			t.Fatal(err)
		}
		for _, j := range []Job{
			{Schedule: "*/5  * * * *", Command: "/bin/true"},
			{Schedule: " */5\t* * * * ", Command: "/bin/true "},
		} {
			if err := Add(j); err == nil {
				t.Errorf("Add(%q, %q) accepted a duplicate", j.Schedule, j.Command)
			}
		}
		if n := strings.Count(g.state, "/bin/true"); n != 1 {
			t.Errorf("crontab holds %d copies, want 1:\n%s", n, g.state)
		}
	})

	t.Run("job is removable with the arguments it was added with", func(t *testing.T) {
		for _, s := range []string{"0  3 * * *", "@daily", "@daily "} {
			g := &wsCrontab{}
			execCommandFn = g.command
			if err := Add(Job{Schedule: s, Command: "/bin/echo  x"}); err != nil {
				t.Fatal(err)
			}
			if err := Remove(s, "/bin/echo  x"); err != nil {
				t.Fatal(err)
			}
			if jobs, _ := List(); len(jobs) != 0 {
				t.Errorf("schedule %q: %d jobs left after Remove", s, len(jobs))
			}
		}
	})

	t.Run("inner command spacing is kept", func(t *testing.T) {
		g := &wsCrontab{}
		execCommandFn = g.command
		if err := Add(Job{Schedule: "0 3 * * *", Command: "/bin/echo  x"}); err != nil {
			t.Fatal(err)
		}
		jobs, _ := List()
		if len(jobs) != 1 || jobs[0].Command != "/bin/echo  x" {
			t.Errorf("jobs = %+v", jobs)
		}
	})
}
