package cronjob

// Regression: List and Remove matched the UWAS marker anywhere in a crontab
// line (strings.Contains) while the marker is only a job marker at the start
// of a line — Add always writes it there, and RemoveByDomain already matched
// it only at the start ("a comment on another domain's job may quote this
// marker text"). A comment elsewhere that quoted the marker text made List
// report the operator's own cron line behind it as a UWAS-managed job, and
// made Remove delete that comment line and the job line although they were
// never UWAS-managed.

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

const quotedMarkerCrontab = "# restored from backup (was # UWAS managed [old.example.com] nightly)\n" +
	"30 2 * * * /usr/local/bin/backup.sh\n" +
	"# UWAS managed [example.com] WP cron\n" +
	"*/5 * * * * /usr/bin/php /var/www/cron.php\n"

// stubCrontabLines answers `crontab -l` with content and captures the crontab
// written by `crontab <file>` into *installed.
func stubCrontabLines(t *testing.T, content string, installed *string) {
	t.Helper()
	origGOOS := runtimeGOOS
	origCmd := execCommandFn
	runtimeGOOS = "linux"
	execCommandFn = func(name string, args ...string) *exec.Cmd {
		if name == "crontab" && len(args) == 1 && args[0] != "-l" {
			if data, err := os.ReadFile(args[0]); err == nil {
				*installed = string(data)
			}
		}
		return fakeExecCommand(content, 0)(name, args...)
	}
	t.Cleanup(func() {
		runtimeGOOS = origGOOS
		execCommandFn = origCmd
	})
}

func TestListMarkerOnlyAtLineStart(t *testing.T) {
	var installed string
	stubCrontabLines(t, quotedMarkerCrontab, &installed)

	jobs, err := List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	// The genuinely-managed job (marker at line start) is listed exactly once.
	var managed int
	for _, j := range jobs {
		if j.Schedule == "*/5 * * * *" && j.Command == "/usr/bin/php /var/www/cron.php" {
			managed++
		}
	}
	if managed != 1 {
		t.Fatalf("UWAS-managed job listed %d times, want 1 (jobs=%+v)", managed, jobs)
	}

	// The manual job behind a comment that only QUOTES the marker must not be
	// attributed to UWAS management.
	for _, j := range jobs {
		if j.Schedule == "30 2 * * *" && j.Command == "/usr/local/bin/backup.sh" {
			t.Fatalf("manual job %q %q listed as UWAS-managed via mid-line marker match (jobs=%+v)",
				j.Schedule, j.Command, jobs)
		}
	}
}

func TestRemoveMarkerOnlyAtLineStart(t *testing.T) {
	var installed string
	stubCrontabLines(t, quotedMarkerCrontab, &installed)

	// Removing the manual job — which the marker contract says is not
	// UWAS-managed — must leave the crontab untouched.
	if err := Remove("30 2 * * *", "/usr/local/bin/backup.sh"); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}
	if installed == "" {
		t.Fatalf("Remove never installed a crontab")
	}

	var keptManaged, keptQuotingComment, keptManualJob int
	for _, line := range strings.Split(installed, "\n") {
		switch {
		case strings.HasPrefix(strings.TrimSpace(line), uwasMarker) && strings.Contains(line, "[example.com]"):
			keptManaged++
		case strings.Contains(line, "restored from backup"):
			keptQuotingComment++
		case strings.TrimSpace(line) == "30 2 * * * /usr/local/bin/backup.sh":
			keptManualJob++
		}
	}
	if keptManaged != 1 {
		t.Fatalf("pre-existing UWAS-managed job must survive removing an unrelated job (kept=%d):\n%s", keptManaged, installed)
	}
	if keptQuotingComment != 1 || keptManualJob != 1 {
		t.Fatalf("Remove deleted non-UWAS lines: quoting comment kept=%d, manual job kept=%d\nwritten crontab:\n%s",
			keptQuotingComment, keptManualJob, installed)
	}
}

// TestRemoveStillRemovesManagedPair pins the affected happy path: a genuine
// marker + job pair is removed, and only that pair.
func TestRemoveStillRemovesManagedPair(t *testing.T) {
	var installed string
	stubCrontabLines(t, quotedMarkerCrontab, &installed)

	if err := Remove("*/5 * * * *", "/usr/bin/php /var/www/cron.php"); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	var keptManagedPair, keptManualLines int
	for _, line := range strings.Split(installed, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, uwasMarker) || trimmed == "*/5 * * * * /usr/bin/php /var/www/cron.php":
			keptManagedPair++
		case trimmed == "30 2 * * * /usr/local/bin/backup.sh" || strings.Contains(trimmed, "restored from backup"):
			keptManualLines++
		}
	}
	if keptManagedPair != 0 {
		t.Fatalf("managed pair not removed (%d lines remain):\n%s", keptManagedPair, installed)
	}
	if keptManualLines != 2 {
		t.Fatalf("removing the managed pair disturbed the unrelated lines (kept=%d):\n%s", keptManualLines, installed)
	}
}
