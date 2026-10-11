package rewrite

import (
	"errors"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/pkg/rxguard"
)

// F14201: the 1024-character pattern limit still admits a 146k-instruction
// program (".{1000}" x 146), compiled and kept for every rule of an .htaccess
// file. Oversized patterns are refused like uncompilable ones.
func TestParseRuleRefusesOversizedPatterns(t *testing.T) {
	heavy := strings.Repeat(`.{1000}`, 146) // 1022 bytes: under the length cap
	if _, err := ParseRule(heavy, "/x", ""); !errors.Is(err, rxguard.ErrTooComplex) {
		t.Errorf("ParseRule: err = %v, want ErrTooComplex", err)
	}
	if _, err := ParseCondition("%{REQUEST_URI}", heavy, ""); !errors.Is(err, rxguard.ErrTooComplex) {
		t.Errorf("ParseCondition: err = %v, want ErrTooComplex", err)
	}
}

func TestParseRuleStillAcceptsOrdinaryPatterns(t *testing.T) {
	for _, p := range []string{`^/blog/([0-9]{4})/(.*)$`, `^(?i)index\.(php|html?)$`, `^/a{1,50}$`, `!^/static/`} {
		if _, err := ParseRule(p, "/x", ""); err != nil {
			t.Errorf("ParseRule(%q): %v", p, err)
		}
	}
	if _, err := ParseCondition("%{HTTP_USER_AGENT}", `(bot|crawler|spider){1,5}`, "NC"); err != nil {
		t.Errorf("ParseCondition: %v", err)
	}
}
