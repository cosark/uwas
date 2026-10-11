package rewrite

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// Rewrite rules come from tenant-written .htaccess files, so the work one
// request can cause has to be bounded (F14500, F14501, F14502).

func stepClock(step time.Duration) func() time.Time {
	t0 := time.Unix(1_700_000_000, 0)
	n := 0
	return func() time.Time {
		cur := t0.Add(time.Duration(n) * step)
		n++
		return cur
	}
}

func mustRule(t *testing.T, pattern, target, flags string, conds ...Condition) *Rule {
	t.Helper()
	r, err := ParseRule(pattern, target, flags)
	if err != nil {
		t.Fatal(err)
	}
	r.Conditions = conds
	return r
}

// F14500: a target that repeats $1, matched again by its own output, used to
// grow the URI by a constant factor on every pass.
func TestSubstitutionGrowthIsBounded(t *testing.T) {
	grow := mustRule(t, "^(.*)$", strings.Repeat("$1", 5), "")
	res := NewEngine([]*Rule{grow}).Process("/a", "", &Variables{RequestURI: "/a"})
	if len(res.URI) > maxRewriteString {
		t.Fatalf("rewritten URI is %d bytes, want <= %d", len(res.URI), maxRewriteString)
	}

	// With a guard in the set the runaway request is refused.
	guard := mustRule(t, `^/never$`, "-", "[F]")
	res = NewEngine([]*Rule{grow, guard}).Process("/a", "", &Variables{RequestURI: "/a"})
	if !res.Forbidden {
		t.Errorf("runaway substitution next to a [F] rule was not refused: %+v", res)
	}

	// Control: an ordinary rewrite is untouched.
	res = NewEngine([]*Rule{mustRule(t, "^/old/(.*)$", "/new/$1", "[L]")}).Process("/old/x", "", &Variables{RequestURI: "/old/x"})
	if res.URI != "/new/x" || res.Forbidden {
		t.Errorf("control rewrite changed: %+v", res)
	}
}

func TestApplyLimited(t *testing.T) {
	r := mustRule(t, "^(.*)$", "x", "")
	got, ok := r.applyLimited("/n/$1", []string{"/a", "/a"}, nil, nil, 100)
	if !ok || got != "/n//a" {
		t.Errorf("small substitution = %q, %v", got, ok)
	}
	if _, ok := r.applyLimited(strings.Repeat("$1", 100), []string{"", strings.Repeat("a", 50)}, nil, nil, 1000); ok {
		t.Error("a 5000-byte substitution passed a 1000-byte bound")
	}
	vars := &Variables{Header: http.Header{"Cookie": {strings.Repeat("c", 4000)}}}
	if _, ok := r.applyLimited(strings.Repeat("%{HTTP_COOKIE}", 20), nil, nil, vars, 10000); ok {
		t.Error("repeated %{HTTP_COOKIE} passed the bound")
	}
	if got, ok := r.applyLimited("$1", []string{"", strings.Repeat("a", 50)}, nil, nil, 0); !ok || len(got) != 50 {
		t.Errorf("limit 0 must mean unbounded, got %d, %v", len(got), ok)
	}
}

// F14501: running out of budget must not skip an [F]/[G] rule.
func TestBudgetExpiryKeepsGuards(t *testing.T) {
	saved := rewriteNow
	defer func() { rewriteNow = saved }()

	guard := mustRule(t, `^secret\.txt$`, "-", "[F]")
	rewrite := mustRule(t, `^a$`, "secret.txt", "")
	e := NewEngine([]*Rule{guard, rewrite})

	rewriteNow = saved
	if res := e.Process("a", "", &Variables{RequestURI: "a"}); !res.Forbidden {
		t.Fatalf("control: guard did not fire with the real clock: %+v", res)
	}

	rewriteNow = stepClock(30 * time.Millisecond)
	if res := e.Process("a", "", &Variables{RequestURI: "a"}); !res.Forbidden {
		t.Errorf("budget ran out and the guard was skipped: %+v", res)
	}

	gone := NewEngine([]*Rule{mustRule(t, `^old$`, "-", "[G]"), rewrite})
	rewriteNow = stepClock(30 * time.Millisecond)
	if res := gone.Process("a", "", &Variables{RequestURI: "a"}); !res.Forbidden {
		t.Errorf("a [G] rule is a guard too: %+v", res)
	}

	// Without a guard the lost rewrite stays lenient: nothing to protect.
	plain := NewEngine([]*Rule{mustRule(t, `^a$`, "b", "")})
	rewriteNow = stepClock(30 * time.Millisecond)
	if res := plain.Process("a", "", &Variables{RequestURI: "a"}); res.Forbidden {
		t.Errorf("a set without a guard was refused: %+v", res)
	}

	rewriteNow = stepClock(60 * time.Millisecond)
	if !e.MightMatch("a") {
		t.Error("MightMatch answered no when it ran out of time")
	}
}

// F14502: the budget is read before each rule, not only between passes.
func TestBudgetIsReadBeforeEachRule(t *testing.T) {
	saved := rewriteNow
	defer func() { rewriteNow = saved }()

	e := NewEngine([]*Rule{
		mustRule(t, `^a$`, "b", ""),
		mustRule(t, `^b$`, "c", ""),
	})
	rewriteNow = saved
	if res := e.Process("a", "", &Variables{RequestURI: "a"}); res.URI != "c" {
		t.Fatalf("control: both rules should apply, URI=%q", res.URI)
	}
	// 20 ms per reading: the first rule's check is still inside the 50 ms
	// budget (readings at 0, 20 and 40 ms), the second rule's is not (60 ms).
	rewriteNow = stepClock(20 * time.Millisecond)
	res := e.Process("a", "", &Variables{RequestURI: "a"})
	if res.URI != "b" {
		t.Errorf("the second rule ran after the budget was spent: URI=%q", res.URI)
	}
}

// F14502: a value too long to match cheaply is over budget, not matched.
func TestOverlongInputsAreOverBudget(t *testing.T) {
	long := strings.Repeat("a", maxRewriteString+1)
	guard := mustRule(t, `^/never$`, "-", "[F]")

	e := NewEngine([]*Rule{guard})
	if res := e.Process("/"+long, "", &Variables{RequestURI: "/" + long}); !res.Forbidden {
		t.Errorf("an over-long URI next to a [F] rule was matched instead of refused: %+v", res)
	}
	if !e.MightMatch("/" + long) {
		t.Error("MightMatch must hand an over-long URI to Process")
	}
	if res := NewEngine([]*Rule{mustRule(t, `^/a$`, "/b", "")}).Process("/"+long, "", &Variables{RequestURI: "/" + long}); res.Forbidden {
		t.Errorf("a set without a guard was refused: %+v", res)
	}

	cond, err := ParseCondition("%{HTTP_COOKIE}", "bad", "")
	if err != nil {
		t.Fatal(err)
	}
	withCond := mustRule(t, `^/x$`, "-", "[F]", *cond)
	vars := &Variables{RequestURI: "/x", Header: http.Header{"Cookie": {long}}}
	if res := NewEngine([]*Rule{withCond}).Process("/x", "", vars); !res.Forbidden {
		t.Errorf("an over-long condition value next to a [F] rule was matched instead of refused: %+v", res)
	}
	vars.Header = http.Header{"Cookie": {"ok"}}
	if res := NewEngine([]*Rule{withCond}).Process("/x", "", vars); res.Forbidden {
		t.Errorf("control: a short non-matching cookie was refused: %+v", res)
	}
	vars.Header = http.Header{"Cookie": {"bad"}}
	if res := NewEngine([]*Rule{withCond}).Process("/x", "", vars); !res.Forbidden {
		t.Errorf("control: a matching cookie was not refused: %+v", res)
	}
}
