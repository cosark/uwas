package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func auditJSONLine(action string) string {
	return `{"time":"2026-10-12T00:00:00Z","action":"` + action + `","detail":"d","success":true}` + "\n"
}

func oversizeAuditLine() string {
	return `{"time":"2026-10-12T00:00:00Z","action":"auth.login.failed","detail":"` +
		strings.Repeat("a", 2<<20) + `","success":false}` + "\n"
}

func replayActions(t *testing.T, dir string) ([]string, error) {
	t.Helper()
	s := newAuditTestServer(t, dir)
	defer s.stopAudit()
	err := s.loadAuditLog()
	var out []string
	for _, e := range s.auditBuf.Snapshot() {
		out = append(out, e.Action)
	}
	return out, err
}

// F15504: bufio.Scanner gives up at the first line over its buffer, and
// loadAuditLog then dropped everything read so far, so one oversized entry
// (an older build wrote them) hid the whole trail after every restart.
func TestAuditReplaySkipsAnOversizeLine(t *testing.T) {
	cases := map[string]string{
		"middle":          auditJSONLine("one") + oversizeAuditLine() + auditJSONLine("two") + auditJSONLine("three"),
		"first":           oversizeAuditLine() + auditJSONLine("one") + auditJSONLine("two") + auditJSONLine("three"),
		"last":            auditJSONLine("one") + auditJSONLine("two") + auditJSONLine("three") + oversizeAuditLine(),
		"no final \\n":    auditJSONLine("one") + auditJSONLine("two") + strings.TrimSuffix(auditJSONLine("three"), "\n"),
		"oversize no \\n": auditJSONLine("one") + auditJSONLine("two") + auditJSONLine("three") + strings.TrimSuffix(oversizeAuditLine(), "\n"),
		"CRLF lines":      strings.ReplaceAll(auditJSONLine("one")+auditJSONLine("two")+auditJSONLine("three"), "\n", "\r\n"),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "audit.log"), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := replayActions(t, dir)
			if err != nil {
				t.Fatalf("replay failed: %v", err)
			}
			want := []string{"one", "two", "three"}
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("replayed %v, want %v", got, want)
			}
		})
	}
}

// An unreadable rotated generation must not discard the other generations.
func TestAuditReplayKeepsOtherGenerationsWhenOneIsUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file modes")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "audit.log.2"), []byte(auditJSONLine("old")), 0o600); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(dir, "audit.log.1")
	if err := os.WriteFile(locked, []byte(auditJSONLine("locked")), 0o000); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "audit.log"), []byte(auditJSONLine("new")), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := replayActions(t, dir)
	if err == nil {
		t.Error("an unreadable generation was not reported")
	}
	if strings.Join(got, ",") != "old,new" {
		t.Fatalf("replayed %v, want [old new]", got)
	}
}
