package admin

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRotateAuditLogWithoutActiveFileKeepsHistory pins the double-rotation
// case: two appenders both saw audit.log over the size limit, the first one
// rotated it, and the second one calls rotateAuditLog when audit.log no longer
// exists. That call has nothing to roll and must not shift the older
// generations (which drops audit.log.3).
func TestRotateAuditLogWithoutActiveFileKeepsHistory(t *testing.T) {
	dir := tempConfigDir(t)
	s := testServer()
	s.configPath = filepath.Join(dir, "uwas.yaml")
	path := s.auditLogFile()

	gens := map[string]string{
		path + ".1": "gen1\n",
		path + ".2": "gen2\n",
		path + ".3": "gen3\n",
	}
	for p, body := range gens {
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}

	// Control: with an active file the roll shifts every generation by one.
	// (Done on a copy of the layout in a second directory.)
	ctlDir := tempConfigDir(t)
	cs := testServer()
	cs.configPath = filepath.Join(ctlDir, "uwas.yaml")
	cpath := cs.auditLogFile()
	for p, body := range gens {
		if err := os.WriteFile(filepath.Join(ctlDir, filepath.Base(p)), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(cpath, []byte("active\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cs.rotateAuditLog(cpath)
	if b, _ := os.ReadFile(cpath + ".1"); string(b) != "active\n" {
		t.Fatalf("control: audit.log.1 = %q, want the rotated active file", b)
	}
	if b, _ := os.ReadFile(cpath + ".3"); string(b) != "gen2\n" {
		t.Fatalf("control: audit.log.3 = %q, want gen2", b)
	}

	// Defect: no active file → nothing to rotate, history must be untouched.
	s.rotateAuditLog(path)
	for p, body := range gens {
		b, err := os.ReadFile(p)
		if err != nil || string(b) != body {
			t.Errorf("EXPECTED: %s = %q\nACTUAL: %q (err=%v)", filepath.Base(p), body, b, err)
		}
	}
}
