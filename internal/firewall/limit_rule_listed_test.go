package firewall

import (
	"os/exec"
	"strings"
	"testing"
)

// A `ufw limit` row must be listed (live and staged); the action recognizer
// used to skip it, so the panel never showed rate-limited ports (F19900).
func TestLimitRulesAreListed(t *testing.T) {
	// live numbered output
	installScopeFake(t,
		"80/tcp                     ALLOW IN    Anywhere",
		"22/tcp                     LIMIT IN    Anywhere",
		"22/tcp (v6)                LIMIT IN    Anywhere (v6)",
		"3306/tcp                   LIMIT IN    203.0.113.10",
		"443/tcp                    ALLOW IN    Anywhere",
	)
	st := GetStatus()
	if len(st.Rules) != 5 {
		t.Fatalf("want 5 rules, got %d: %+v", len(st.Rules), st.Rules)
	}
	l := st.Rules[1]
	if l.Action != "LIMIT" || l.Port != "22" || l.Proto != "tcp" || l.Number != 2 || l.From != "Anywhere" {
		t.Fatalf("bad limit rule: %+v", l)
	}
	if !st.Rules[2].V6 || st.Rules[2].Action != "LIMIT" {
		t.Fatalf("bad v6 limit rule: %+v", st.Rules[2])
	}
	// edge: source-restricted limit keeps its From
	if st.Rules[3].From != "203.0.113.10" || st.Rules[3].Action != "LIMIT" {
		t.Fatalf("bad from limit rule: %+v", st.Rules[3])
	}
	// edge: neighbours unchanged
	if st.Rules[0].Action != "ALLOW" || st.Rules[4].Action != "ALLOW" {
		t.Fatalf("neighbours changed: %+v", st.Rules)
	}

	// 2. staged (ufw inactive) path
	execCommandFn = func(_ string, arg ...string) *exec.Cmd {
		switch strings.Join(arg, " ") {
		case "status numbered":
			return exec.Command("printf", "%s", "Status: inactive\n")
		case "show added":
			return exec.Command("printf", "%s", "Added user rules (see 'ufw status' for running firewall):\nufw limit 22/tcp\nufw allow 80/tcp\n")
		}
		return exec.Command("true")
	}
	st = GetStatus()
	if !st.Staged || len(st.Rules) != 2 || st.Rules[0].Action != "LIMIT" || st.Rules[0].Port != "22" || st.Rules[1].Action != "ALLOW" {
		t.Fatalf("staged limit rule wrong: %+v", st)
	}

	// 3. moving a LIMIT row is refused cleanly, never recreated as another action
	if _, err := ruleToUFWArgs(Rule{Action: "LIMIT", Port: "22", Proto: "tcp"}); err == nil {
		t.Fatal("ruleToUFWArgs must refuse LIMIT")
	}
}
