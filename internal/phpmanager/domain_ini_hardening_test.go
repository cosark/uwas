package phpmanager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildINIForTest renders the per-domain ini for domain rooted at root on top
// of a base php.ini with the given text, and returns it as a string.
func buildINIForTest(t *testing.T, domain, root, base string, overrides map[string]string) string {
	t.Helper()
	m := New(testLogger())
	m.RegisterExistingDomain(domain, "8.4", "127.0.0.1:9001", root, overrides)
	cfg := filepath.Join(t.TempDir(), "php.ini")
	if err := os.WriteFile(cfg, []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	m.domainMu.Lock()
	p, err := m.buildDomainINI(domain, PHPInstall{Version: "8.4", ConfigFile: cfg}, m.domainMap[domain].configOverrides)
	m.domainMu.Unlock()
	if err != nil {
		t.Fatalf("buildDomainINI: %v", err)
	}
	defer os.Remove(p)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// iniValue returns the last-wins value of key in an ini text.
func iniValue(ini, key string) (string, bool) {
	val, found := "", false
	for _, line := range strings.Split(ini, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == key {
			val, found = strings.TrimSpace(v), true
		}
	}
	return val, found
}

// F11500: open_basedir entries are string prefixes. Without a trailing
// separator "/var/www/example.com" also admits the sibling tenant
// "/var/www/example.com.au" (PHP manual: end the entry with a slash to
// restrict access to that directory).
func TestOpenBasedirEntriesAreDirectoryScoped(t *testing.T) {
	parent := t.TempDir()
	a := filepath.Join(parent, "example.com")
	sibling := filepath.Join(parent, "example.com.au")
	for _, d := range []string{a, sibling} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ini := buildINIForTest(t, "example.com", a, "memory_limit = 128M\n", nil)
	val, ok := iniValue(ini, "open_basedir")
	if !ok {
		t.Fatal("no open_basedir emitted")
	}
	entries := strings.Split(val, ":")

	if entries[0] != a+"/" {
		t.Errorf("web root entry = %q, want %q", entries[0], a+"/")
	}
	if entries[1] != filepath.Join(a, ".tmp")+"/" {
		t.Errorf("tmp entry = %q, want %q", entries[1], filepath.Join(a, ".tmp")+"/")
	}
	for _, e := range entries {
		if e == "/dev/urandom" { // a file, not a directory
			continue
		}
		if !strings.HasSuffix(e, "/") {
			t.Errorf("open_basedir entry %q lacks a trailing separator and admits every path it prefixes", e)
		}
		// The sibling tenant must not be reachable through any entry. (The
		// shared /tmp/ entry legitimately covers t.TempDir() itself.)
		if e != "/tmp/" && strings.HasPrefix(sibling+"/wp-config.php", e) {
			t.Errorf("entry %q admits sibling tenant %q", e, sibling)
		}
	}
	// The domain's own files stay reachable.
	if !strings.HasPrefix(filepath.Join(a, "index.php"), entries[0]) {
		t.Errorf("own file not admitted by %q", entries[0])
	}
}

func TestOpenBasedirDirKeepsSingleSeparator(t *testing.T) {
	for in, want := range map[string]string{
		"/srv/site":  "/srv/site/",
		"/srv/site/": "/srv/site/",
		"/":          "/",
	} {
		if got := openBasedirDir(in); got != want {
			t.Errorf("openBasedirDir(%q) = %q, want %q", in, got, want)
		}
	}
}

// F11501: sessions are moved into <root>/.tmp, which nothing else cleans. A
// base php.ini that disables PHP's own session GC (Debian/Ubuntu ship
// gc_probability = 0 and rely on a cron job for the system directory) would
// leave them to pile up.
func TestSessionGCRestoredOnlyWhenBaseDisablesIt(t *testing.T) {
	cases := []struct {
		name     string
		base     string
		wantProb string // "" = no gc_probability line expected from UWAS
		wantDiv  string
	}{
		{"debian default disables gc", "session.gc_probability = 0\nsession.gc_divisor = 1000\n", "1", "1000"},
		{"trailing comment", "session.gc_probability = 0 ; cron cleans it\n", "1", "1000"},
		{"quoted zero", "session.gc_probability = \"0\"\n", "1", "1000"},
		{"last assignment wins (re-enabled)", "session.gc_probability = 0\nsession.gc_probability = 1\n", "1", ""},
		{"last assignment wins (disabled)", "session.gc_probability = 1\nsession.gc_probability = 0\n", "1", "1000"},
		{"operator tuning is left alone", "session.gc_probability = 5\nsession.gc_divisor = 50\n", "5", "50"},
		{"not mentioned: PHP default applies", "memory_limit = 128M\n", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ini := buildINIForTest(t, "gc.test", t.TempDir(), c.base, nil)
			prob, hadProb := iniValue(ini, "session.gc_probability")
			div, _ := iniValue(ini, "session.gc_divisor")
			if c.wantProb == "" {
				if hadProb {
					t.Fatalf("unexpected session.gc_probability = %q", prob)
				}
				return
			}
			if prob != c.wantProb {
				t.Errorf("effective session.gc_probability = %q, want %q", prob, c.wantProb)
			}
			if c.wantDiv != "" && div != c.wantDiv {
				t.Errorf("effective session.gc_divisor = %q, want %q", div, c.wantDiv)
			}
		})
	}
}

// A per-domain override still wins over the restored default: overrides are
// emitted after the enforced block.
func TestSessionGCOverrideStillWins(t *testing.T) {
	ini := buildINIForTest(t, "gc.test", t.TempDir(), "session.gc_probability = 0\n",
		map[string]string{"session.gc_probability": "3"})
	if prob, _ := iniValue(ini, "session.gc_probability"); prob != "3" {
		t.Errorf("effective session.gc_probability = %q, want the override 3", prob)
	}
}

// F11502: native-code loading directives that sit in the same
// PHP_INI_SYSTEM scope as the already blocked ffi.enable.
func TestNativeCodeDirectivesBlocked(t *testing.T) {
	root := t.TempDir()
	keys := []string{"ffi.preload", "sqlite3.extension_dir"}
	seed := map[string]string{"memory_limit": "256M"}
	for _, k := range keys {
		seed[k] = filepath.Join(root, "x")
	}
	m := New(testLogger())
	m.RegisterExistingDomain("native.test", "8.4", "127.0.0.1:9001", root, seed)
	for _, k := range keys {
		if INIOverrideAllowed(k, "/x") || INIOverrideAllowed(strings.ToUpper(k), "/x") {
			t.Errorf("INIOverrideAllowed accepted %s", k)
		}
		if err := m.SetDomainConfig("native.test", k, "/x"); err == nil {
			t.Errorf("SetDomainConfig accepted %s", k)
		}
	}
	if err := m.SetDomainConfig("native.test", "memory_limit", "512M"); err != nil {
		t.Errorf("control: memory_limit rejected: %v", err)
	}

	ini := buildINIForTest(t, "native.test", root, "memory_limit = 128M\n", seed)
	for _, k := range keys {
		if strings.Contains(ini, k+" =") {
			t.Errorf("config-seeded %s emitted into the ini", k)
		}
	}
	if v, _ := iniValue(ini, "memory_limit"); v != "256M" {
		t.Errorf("control: memory_limit = %q, want 256M", v)
	}
}
