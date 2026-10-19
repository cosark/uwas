package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
	"github.com/uwaserver/uwas/internal/metrics"
	"github.com/uwaserver/uwas/internal/phpmanager"
)

func newPHPOverrideServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Global: config.GlobalConfig{Admin: config.AdminConfig{Listen: "127.0.0.1:0"}, WebRoot: dir},
		Domains: []config.Domain{
			{Host: "example.com", Type: "php", Root: filepath.Join(dir, "example.com"), SSL: config.SSLConfig{Mode: "auto"},
				PHP: config.PHPConfig{FPMAddress: "unix:/run/php/x.sock"}},
			{Host: "other.com", Type: "php", Root: filepath.Join(dir, "other.com"), SSL: config.SSLConfig{Mode: "auto"},
				PHP: config.PHPConfig{FPMAddress: "unix:/run/php/y.sock", ConfigOverrides: map[string]string{"memory_limit": "64M"}}},
		},
	}
	log := logger.New("error", "text")
	srv := New(cfg, log, metrics.New())
	srv.SetPHPManager(phpmanager.New(log))
	srv.configPath = filepath.Join(dir, "uwas.yaml")
	srv.phpMgr.RegisterExistingDomain("example.com", "8.3", "unix:/run/php/x.sock", dir, nil)
	srv.phpMgr.RegisterExistingDomain("other.com", "8.3", "unix:/run/php/y.sock", dir, map[string]string{"memory_limit": "64M"})
	if err := srv.persistConfig(); err != nil {
		t.Fatalf("persistConfig: %v", err)
	}
	return srv, dir
}

func readDomainFile(t *testing.T, dir, host string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "domains.d", host+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A per-domain php.ini override saved through the PHP admin API must survive
// the next persistConfig, which rewrites every domain file from s.config.
func TestPHPOverrideSurvivesLaterPersistConfig(t *testing.T) {
	srv, dir := newPHPOverrideServer(t)
	if err := srv.phpMgr.SetDomainConfig("example.com", "memory_limit", "512M"); err != nil {
		t.Fatal(err)
	}
	srv.persistDomainPHPOverrides("example.com")
	if !strings.Contains(readDomainFile(t, dir, "example.com"), "512M") {
		t.Fatal("override missing right after persistDomainPHPOverrides")
	}
	// Any later config write: a domain add/update, a settings change.
	for i := 0; i < 2; i++ {
		if err := srv.persistConfig(); err != nil {
			t.Fatal(err)
		}
		if got := readDomainFile(t, dir, "example.com"); !strings.Contains(got, "512M") {
			t.Fatalf("override lost after persistConfig #%d:\n%s", i+1, got)
		}
	}
	// The sibling domain keeps its own overrides.
	if got := readDomainFile(t, dir, "other.com"); !strings.Contains(got, "64M") || strings.Contains(got, "512M") {
		t.Fatalf("sibling domain overrides changed:\n%s", got)
	}
}

// The in-memory copy must not alias the PHP manager's map, and an unknown
// domain must leave the config untouched.
func TestPHPOverridePersistIsolation(t *testing.T) {
	srv, dir := newPHPOverrideServer(t)
	if err := srv.phpMgr.SetDomainConfig("example.com", "memory_limit", "512M"); err != nil {
		t.Fatal(err)
	}
	srv.persistDomainPHPOverrides("example.com")
	// A later manager-side change that is not persisted must not leak into the config.
	if err := srv.phpMgr.SetDomainConfig("example.com", "max_execution_time", "99"); err != nil {
		t.Fatal(err)
	}
	if err := srv.persistConfig(); err != nil {
		t.Fatal(err)
	}
	if got := readDomainFile(t, dir, "example.com"); strings.Contains(got, "max_execution_time") {
		t.Fatalf("unpersisted manager change leaked into config:\n%s", got)
	}
	before := readDomainFile(t, dir, "other.com")
	srv.persistDomainPHPOverrides("ghost.example")
	if err := srv.persistConfig(); err != nil {
		t.Fatal(err)
	}
	if after := readDomainFile(t, dir, "other.com"); after != before {
		t.Fatalf("unknown domain changed another domain file:\n%s\n---\n%s", before, after)
	}
}
