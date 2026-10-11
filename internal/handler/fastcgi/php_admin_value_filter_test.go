package fastcgi

import (
	"strings"
	"testing"
)

// F12001: custom PHP_ADMIN_VALUE lines use the same allowlist as the generated
// pool ini, and "\r" ends an entry like "\n" does.
func TestFilterCustomPHPAdminValueUsesINIAllowlist(t *testing.T) {
	kept := []string{"memory_limit = 256M", "post_max_size=64M", "error_reporting = E_ALL & ~E_NOTICE"}
	dropped := []string{
		"open_basedir = /", "disable_functions =", "disable_classes = X", "enable_dl = 1",
		"allow_url_include = 1", "auto_prepend_file = /tmp/x.php", "auto_append_file = /tmp/x.php",
		"sendmail_path = /tmp/evil.sh", "ffi.preload = /tmp/x.h", "sqlite3.extension_dir = /tmp",
		"extension_dir = /tmp", "error_log = /var/www/other/wp-config.php", "session.save_path = /tmp",
		"upload_tmp_dir = /tmp", "opcache.preload = /tmp/p.php", "OPEN_BASEDIR = /",
		"not an ini line", "bad key! = 1",
	}
	got := filterCustomPHPAdminValue(strings.Join(append(append([]string{}, kept...), dropped...), "\n"))
	if len(got) != len(kept) {
		t.Fatalf("kept %d lines %q, want exactly %q", len(got), got, kept)
	}
	for i, want := range kept {
		if got[i] != want {
			t.Errorf("line %d = %q, want %q", i, got[i], want)
		}
	}
}

func TestFilterCustomPHPAdminValueSplitsOnCarriageReturn(t *testing.T) {
	got := filterCustomPHPAdminValue("memory_limit = 1M\rdisable_functions =\r\nopen_basedir = /")
	if len(got) != 1 || got[0] != "memory_limit = 1M" {
		t.Fatalf("got %q, want only memory_limit = 1M", got)
	}
}
