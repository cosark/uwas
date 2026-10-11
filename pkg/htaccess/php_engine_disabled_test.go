package htaccess

import (
	"strings"
	"testing"
)

func parseRules(t *testing.T, src string) *RuleSet {
	t.Helper()
	dirs, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	return Convert(dirs)
}

// F12100: the usual "no PHP in uploads/" protection must be understood.
func TestPHPDisabledDirectives(t *testing.T) {
	cases := []struct {
		name, src string
		want      bool
	}{
		{"php_flag engine off", "php_flag engine off\n", true},
		{"php_flag engine 0", "php_flag engine 0\n", true},
		{"php_value engine Off", "php_value engine Off\n", true},
		{"RemoveHandler .php", "RemoveHandler .php\n", true},
		{"RemoveHandler several", "RemoveHandler .phtml .php5\n", true},
		{"RemoveHandler without dot", "RemoveHandler php\n", true},
		{"SetHandler none", "SetHandler none\n", true},
		{"SetHandler default-handler", "SetHandler default-handler\n", true},
		{"IfModule mod_php7.c", "<IfModule mod_php7.c>\nphp_flag engine off\n</IfModule>\n", true},
		{"IfModule php_module", "<IfModule php_module>\nphp_flag engine Off\n</IfModule>\n", true},
		// Controls: nothing that disables PHP.
		{"engine on", "php_flag engine on\n", false},
		{"RemoveHandler other extension", "RemoveHandler .html\n", false},
		{"SetHandler for FPM", "SetHandler application/x-httpd-php\n", false},
		{"unrelated php_flag", "php_flag display_errors off\n", false},
		{"IfModule unloaded non-php module", "<IfModule mod_nope.c>\nphp_flag engine off\n</IfModule>\n", false},
		{"negated mod_php block", "<IfModule !mod_php7.c>\nphp_flag engine off\n</IfModule>\n", true}, // not loaded: block applies
	}
	for _, c := range cases {
		rs := parseRules(t, c.src)
		if got := PHPDisabledFor([]*RuleSet{rs}); got != c.want {
			t.Errorf("%s: PHPDisabledFor = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPHPEngineIsNotForwardedAsIniSetting(t *testing.T) {
	rs := parseRules(t, "php_flag engine off\nphp_flag display_errors on\n")
	if _, ok := rs.PHPFlags["engine"]; ok {
		t.Errorf("engine reached PHPFlags: %v", rs.PHPFlags)
	}
	if rs.PHPFlags["display_errors"] != "1" {
		t.Errorf("display_errors lost: %v", rs.PHPFlags)
	}
}

func TestPHPDisabledDeepestLevelWins(t *testing.T) {
	root := parseRules(t, "php_flag engine off\n")
	sub := parseRules(t, "php_flag engine on\n")
	silent := parseRules(t, "# nothing\n")
	if !PHPDisabledFor([]*RuleSet{root, silent}) {
		t.Error("a silent subdirectory must inherit the parent's engine off")
	}
	if PHPDisabledFor([]*RuleSet{root, sub}) {
		t.Error("engine on in a subdirectory must lift the parent's engine off")
	}
	if PHPDisabledFor([]*RuleSet{nil, silent}) {
		t.Error("no level says anything: PHP stays enabled")
	}
	// Merge (split <IfModule> blocks into one RuleSet): the later one wins too.
	merged := parseRules(t, "php_flag engine off\n")
	merged.Merge(parseRules(t, "php_flag engine on\n"))
	if PHPDisabledFor([]*RuleSet{merged}) {
		t.Error("Merge dropped the later engine on")
	}
}
