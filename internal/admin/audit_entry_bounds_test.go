package admin

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// F15503: audit entries carry request-controlled text. A public login request
// with a 900 KB username must not become a 900 KB entry in the in-memory ring
// and in audit.log.
func TestAuditEntryFieldsAreBounded(t *testing.T) {
	dir := t.TempDir()
	s := newAuditTestServer(t, dir)
	defer s.stopAudit()

	huge := strings.Repeat("a", 900_000)
	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	req.RemoteAddr = "198.51.100.8:4444"
	s.RecordAuditR(req, "auth.login.failed", "user="+huge+": invalid credentials", false)
	s.RecordAuditUser(huge, huge, huge, huge, false)

	for i, e := range s.auditBuf.Snapshot() {
		if len(e.Detail) > maxAuditDetail+64 || len(e.User) > maxAuditUser+64 ||
			len(e.Action) > maxAuditAction+64 || len(e.IP) > maxAuditIP+64 {
			t.Errorf("entry %d not bounded: detail=%d user=%d action=%d ip=%d",
				i, len(e.Detail), len(e.User), len(e.Action), len(e.IP))
		}
		if !strings.Contains(e.Detail, "[truncated") {
			t.Errorf("entry %d detail carries no truncation marker", i)
		}
	}
	fi, err := os.Stat(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > 16*1024 {
		t.Errorf("audit.log grew to %d bytes for two requests", fi.Size())
	}
}

// Ordinary entries are untouched, and clipping never splits a UTF-8 character.
func TestClipAudit(t *testing.T) {
	if got := clipAudit("user=alice: wrong password", maxAuditDetail); got != "user=alice: wrong password" {
		t.Errorf("short value changed: %q", got)
	}
	exact := strings.Repeat("x", maxAuditDetail)
	if got := clipAudit(exact, maxAuditDetail); got != exact {
		t.Error("value at the limit was clipped")
	}
	// "é" is two bytes; a limit that falls between them must back up.
	in := strings.Repeat("é", 100)
	got := clipAudit(in, 101)
	if !utf8.ValidString(got) {
		t.Errorf("clip produced invalid UTF-8: %q", got)
	}
	if !strings.HasPrefix(got, strings.Repeat("é", 50)) || !strings.Contains(got, "[truncated") {
		t.Errorf("unexpected clip result: %q", got)
	}
}
