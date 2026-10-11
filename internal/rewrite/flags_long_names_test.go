package rewrite

import "testing"

// F7001: mod_rewrite accepts long flag names; they used to be ignored, so a
// "[forbidden]" guard forbade nothing and an "[ornext]" condition became AND.
func TestLongFlagNamesMatchShortOnes(t *testing.T) {
	vars := &Variables{HTTPReferer: "http://b.example/"}
	run := func(pattern, uri, flags string, conds ...[3]string) *Result {
		t.Helper()
		rule, err := ParseRule(pattern, "-", flags)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range conds {
			cond, err := ParseCondition(c[0], c[1], c[2])
			if err != nil {
				t.Fatal(err)
			}
			rule.Conditions = append(rule.Conditions, *cond)
		}
		return NewEngine([]*Rule{rule}).Process(uri, "", vars)
	}
	ref := "%{HTTP_REFERER}"

	for _, flags := range []string{"F", "forbidden", "Forbidden", "FORBIDDEN"} {
		if !run(`^secret\.txt$`, "secret.txt", flags).Forbidden {
			t.Errorf("[%s] did not forbid", flags)
		}
	}
	if !run(`^gone\.txt$`, "gone.txt", "gone").Gone {
		t.Error("[gone] did not return 410")
	}
	for _, flags := range []string{"R=301", "redirect=301", "Redirect=301"} {
		if got := run(`^old$`, "old", flags); !got.Redirect || got.StatusCode != 301 {
			t.Errorf("[%s]: redirect=%v status=%d, want 301", flags, got.Redirect, got.StatusCode)
		}
	}
	if !run(`^SECRET\.txt$`, "secret.txt", "nocase,F").Forbidden {
		t.Error("[nocase,F] did not match case-insensitively")
	}
	if got := run(`^a$`, "a", "last,qsappend"); got.Forbidden || got.Redirect {
		t.Errorf("[last,qsappend] must neither forbid nor redirect: %+v", got)
	}

	// RewriteCond [ornext] / [nocase]: (A OR B) must forbid with either match.
	for _, orFlag := range []string{"OR", "ornext"} {
		got := run(`^secret\.txt$`, "secret.txt", "F",
			[3]string{ref, `a\.example`, orFlag}, [3]string{ref, `b\.example`, ""})
		if !got.Forbidden {
			t.Errorf("RewriteCond [%s]: second alternative did not forbid", orFlag)
		}
	}
	if !run(`^secret\.txt$`, "secret.txt", "F", [3]string{ref, `B\.EXAMPLE`, "nocase"}).Forbidden {
		t.Error("RewriteCond [nocase] was case-sensitive")
	}

	// Control: a condition that does not hold still stops the rule.
	if run(`^secret\.txt$`, "secret.txt", "forbidden", [3]string{ref, `c\.example`, ""}).Forbidden {
		t.Error("forbidden despite a failing condition")
	}
}
