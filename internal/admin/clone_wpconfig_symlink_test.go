package admin

// Regression test for F5301: detectWordPressDB reads wp-config.php from the
// tenant-writable source docroot as root. A symlink to another site's
// wp-config.php must not make the clone adopt that site's database
// credentials; oversized or special files must be refused rather than read.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/migrate"
)

const wpCfgFmt = "<?php\ndefine('DB_NAME', '%s');\ndefine('DB_USER', '%s');\ndefine('DB_PASSWORD', '%s');\n"

func writeWPConfig(t *testing.T, dir, db, user, pw string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "wp-config.php")
	if err := os.WriteFile(p, []byte(fmt.Sprintf(wpCfgFmt, db, user, pw)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDetectWordPressDBRefusesSymlinkOutsideRoot(t *testing.T) {
	base := t.TempDir()
	victim := writeWPConfig(t, filepath.Join(base, "victim"), "victim_db", "victim_user", "victim_pw")
	attacker := filepath.Join(base, "attacker")
	if err := os.MkdirAll(attacker, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(attacker, "wp-config.php")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	req := &migrate.CloneRequest{SourceRoot: attacker}
	err := detectWordPressDB(req)
	if err == nil || !strings.Contains(err.Error(), "outside the source root") {
		t.Fatalf("err = %v, want outside-the-source-root refusal", err)
	}
	if req.SourceDB != "" || req.DBUser != "" || req.DBPass != "" {
		t.Errorf("adopted victim credentials: %+v", req)
	}
}

func TestDetectWordPressDBAcceptsRegularAndInRootSymlink(t *testing.T) {
	root := t.TempDir()
	writeWPConfig(t, filepath.Join(root, "shared"), "own_db", "own_user", "own_pw")
	req := &migrate.CloneRequest{SourceRoot: root}
	if err := os.Symlink(filepath.Join(root, "shared", "wp-config.php"), filepath.Join(root, "wp-config.php")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := detectWordPressDB(req); err != nil || req.SourceDB != "own_db" || req.DBUser != "own_user" || req.DBPass != "own_pw" {
		t.Fatalf("in-root symlink: err=%v req=%+v", err, req)
	}

	plain := t.TempDir()
	writeWPConfig(t, plain, "plain_db", "u", "p")
	req = &migrate.CloneRequest{SourceRoot: plain}
	if err := detectWordPressDB(req); err != nil || req.SourceDB != "plain_db" {
		t.Fatalf("regular file: err=%v req=%+v", err, req)
	}

	req = &migrate.CloneRequest{SourceRoot: t.TempDir()}
	if err := detectWordPressDB(req); err != nil || req.SourceDB != "" {
		t.Fatalf("missing file: err=%v req=%+v", err, req)
	}
}

func TestDetectWordPressDBRefusesOversizedConfig(t *testing.T) {
	root := t.TempDir()
	big := "<?php\n// " + strings.Repeat("x", wpConfigMaxBytes) + "\ndefine('DB_NAME','late_db');\n"
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"), []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	req := &migrate.CloneRequest{SourceRoot: root}
	if err := detectWordPressDB(req); err == nil || req.SourceDB != "" {
		t.Fatalf("oversized config: err=%v req=%+v", err, req)
	}
}
