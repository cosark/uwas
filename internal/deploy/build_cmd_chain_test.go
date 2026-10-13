package deploy

// deployGit ran an explicit DeployRequest.BuildCmd verbatim through
// runShell -> validateShellCommand, which rejects chaining metacharacters —
// while the BuildCmd doc comment documents `e.g. "npm install && npm run
// build"` as the example. The documented example failed the deploy with
// 'command contains forbidden shell metacharacter: "&&"'. The explicit
// command is now split on "&&" into sequential steps, the same shape
// detectBuildCmds returns for auto-detected builds. These tests pin the
// chained-example behavior and the unaffected plain-command path.

import (
	"strings"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/logger"
)

func chainStubs(shellCmds *[]string) (restore func()) {
	origCmd, origShell, origWait := runCmdFn, runShellFn, waitForAppFn
	runCmdFn = func(dir string, env map[string]string, name string, args ...string) (string, error) {
		return "", nil // git clone/pull stubbed: no process runs
	}
	runShellFn = func(dir string, env map[string]string, command string) (string, error) {
		// Mirror runShellImpl's real gate so the assertions cover the
		// production validation, not just the shape of the input.
		if err := validateShellCommand(command); err != nil {
			return "", err
		}
		*shellCmds = append(*shellCmds, command)
		return "build output", nil
	}
	waitForAppFn = func(addr string, timeout time.Duration) error { return nil }
	return func() { runCmdFn, runShellFn, waitForAppFn = origCmd, origShell, origWait }
}

func chainLogger() *logger.Logger { return logger.New("error", "text") }

func TestDeployGitChainedBuildCmdRunsAsSteps(t *testing.T) {
	var shellCmds []string
	restore := chainStubs(&shellCmds)
	defer restore()

	m := New(chainLogger())
	appRoot := t.TempDir()
	req := DeployRequest{
		Domain:    "app.test",
		GitURL:    "https://github.com/u/repo.git",
		GitBranch: "main",
		BuildCmd:  "npm install && npm run build",
	}
	status := &DeployStatus{Domain: req.Domain}

	err := m.deployGit(req, appRoot, "main", make(chan struct{}), status, &strings.Builder{})
	if err != nil {
		t.Fatalf("chained build command rejected: %v", err)
	}
	got := strings.Join(shellCmds, " | ")
	if !strings.Contains(got, "npm install") || !strings.Contains(got, "npm run build") {
		t.Fatalf("build steps missing; ran: [%s]", got)
	}
	for _, c := range shellCmds {
		if strings.Contains(c, "&&") {
			t.Fatalf("chained command passed through unsplit: %q", c)
		}
	}
}

func TestDeployGitPlainBuildCmdUnchanged(t *testing.T) {
	var shellCmds []string
	restore := chainStubs(&shellCmds)
	defer restore()

	m := New(chainLogger())
	appRoot := t.TempDir()
	req := DeployRequest{
		Domain:    "app.test",
		GitURL:    "https://github.com/u/repo.git",
		GitBranch: "main",
		BuildCmd:  "npm run build",
	}
	status := &DeployStatus{Domain: req.Domain}
	err := m.deployGit(req, appRoot, "main", make(chan struct{}), status, &strings.Builder{})
	if err != nil {
		t.Fatalf("plain build command rejected: %v", err)
	}
	if len(shellCmds) != 1 || shellCmds[0] != "npm run build" {
		t.Fatalf("expected exactly one step %q, got %v", "npm run build", shellCmds)
	}
}
