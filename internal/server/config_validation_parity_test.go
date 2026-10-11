package server

import (
	"sort"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
	"github.com/uwaserver/uwas/internal/middleware"
)

// config validation rejects a security.waf.rules name the WAF does not have
// (F13502), and config cannot import middleware, so it carries its own list.
// The two must stay the same set or validation either lets a typo through or
// refuses a real family.
func TestConfigWAFRuleNamesMatchTheWAF(t *testing.T) {
	want := middleware.WAFRuleNames()
	got := config.WAFRuleNames()
	sort.Strings(want)
	sort.Strings(got)
	if len(want) != len(got) {
		t.Fatalf("config knows %v, the WAF has %v", got, want)
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("config knows %v, the WAF has %v", got, want)
		}
	}
	for _, name := range want {
		if !config.KnownWAFRuleName(name) || !middleware.KnownWAFRule(name) {
			t.Errorf("%q is not known to both", name)
		}
	}
}

func TestLogConfigWarningsToleratesMissingPieces(t *testing.T) {
	logConfigWarnings(nil, &config.Config{Warnings: []string{"x"}})
	logConfigWarnings(logger.New("error", "text"), nil)
	logConfigWarnings(logger.New("error", "text"), &config.Config{Warnings: []string{"a.yaml: unknown key ignored: line 3: field foo not found in type config.Domain"}})
}
