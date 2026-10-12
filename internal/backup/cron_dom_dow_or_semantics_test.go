package backup

// Regression: nextCronRun ANDed the day-of-month and day-of-week fields.
//
// POSIX/Vixie crontab ORs them when BOTH are restricted (man 5 crontab: "if
// both fields are restricted (i.e., aren't *), the command will be run when
// either field matches"). UWAS required both to match, so an operator's
// "0 0 13 * 5" — the 13th of the month OR every Friday — fired only on a
// Friday that happened to be the 13th: a handful of runs a year instead of
// every Friday plus the 13th, and a schedule that can silently never fire.
//
// The same POSIX baseline already governs this function's weekday handling —
// see cron_weekday7_range_test.go and cron_bare_alias_scope_test.go.
//
// The other case is unchanged: a bare "*" in either field is unrestricted, so
// POSIX collapses to the plain AND (the untouched branch in nextCronRun).

import (
	"testing"
	"time"
)

// firstDOMorDOW states the POSIX rule independently, in plain calendar
// arithmetic with no cron matcher involved, so the assertion does not restate
// the implementation.
func firstDOMorDOW(from time.Time, dom int, dow time.Weekday) time.Time {
	day := time.Date(from.Year(), from.Month(), from.Day(), 0, 0, 0, 0, from.Location())
	for i := 1; i <= 400; i++ {
		c := day.AddDate(0, 0, i)
		if c.Day() == dom || c.Weekday() == dow {
			return c
		}
	}
	return time.Time{}
}

func TestNextCronRunRestrictedDOMAndDOWAreOred(t *testing.T) {
	const expr = "0 0 13 * 5" // 00:00 on the 13th OR every Friday

	got := nextCronRun(expr)
	if got.IsZero() {
		t.Fatalf("nextCronRun(%q) returned the zero time — schedule never fires", expr)
	}

	want := firstDOMorDOW(time.Now(), 13, time.Friday)
	if want.IsZero() {
		t.Fatal("test harness could not compute a reference date")
	}
	want = time.Date(want.Year(), want.Month(), want.Day(), 0, 0, 0, 0, want.Location())

	if !got.Equal(want) {
		t.Fatalf("nextCronRun(%q) = %v (%s), want the first day matching dom OR dow = %v (%s)",
			expr, got, got.Weekday(), want, want.Weekday())
	}
}

// A weekday-restricted run must land within a week: with the 13th OR'd in, the
// nearest matching day is never further away than the next Friday.
func TestNextCronRunRestrictedDOMAndDOWStayWithinAWeek(t *testing.T) {
	next := nextCronRun("30 2 13 * 5")
	if next.IsZero() {
		t.Fatal(`nextCronRun("30 2 13 * 5") returned zero`)
	}
	if d := time.Until(next); d <= 0 || d > 7*24*time.Hour {
		t.Fatalf("next run is %v away, want at most 7 days (the next Friday)", d)
	}
	if next.Hour() != 2 || next.Minute() != 30 {
		t.Fatalf("next run time = %02d:%02d, want 02:30", next.Hour(), next.Minute())
	}
}

// nextCronRun must never report zero for an expression that has a firing day.
// Without the OR this "0 0 31 2 *" (the 31st OR any Friday in February) could
// land on a date that is neither, and only the two-year scan ended the walk.
func TestNextCronRunFindsADayForImpossibleDOMWithRestrictedDOW(t *testing.T) {
	next := nextCronRun("0 0 31 2 5")
	if next.IsZero() {
		t.Fatal(`nextCronRun("0 0 31 2 5") returned zero — February never has a 31st, but every Friday matches`)
	}
	if next.Month() != time.February {
		t.Fatalf("next run month = %v, want February", next.Month())
	}
	if next.Weekday() != time.Friday {
		t.Fatalf("next run weekday = %v, want Friday (February 31 never occurs)", next.Weekday())
	}
}

// Controls: a bare "*" in either field leaves the plain AND in place, so the
// single-restriction cases must be unchanged by the OR branch.
func TestNextCronRunSingleRestrictionUnaffected(t *testing.T) {
	t.Run("weekday only", func(t *testing.T) {
		next := nextCronRun("0 0 * * 5")
		if next.IsZero() {
			t.Fatal(`nextCronRun("0 0 * * 5") returned zero`)
		}
		if next.Weekday() != time.Friday || next.Hour() != 0 || next.Minute() != 0 {
			t.Fatalf("next run = %v, want a Friday 00:00", next)
		}
		if d := time.Until(next); d > 7*24*time.Hour {
			t.Fatalf("next run is %v away, want at most 7 days", d)
		}
	})

	t.Run("day of month only", func(t *testing.T) {
		next := nextCronRun("0 0 13 * *")
		if next.IsZero() {
			t.Fatal(`nextCronRun("0 0 13 * *") returned zero`)
		}
		if next.Day() != 13 || next.Hour() != 0 || next.Minute() != 0 {
			t.Fatalf("next run = %v, want the 13th at 00:00", next)
		}
	})

	t.Run("both fields bare star", func(t *testing.T) {
		next := nextCronRun("0 0 * * *")
		if next.IsZero() {
			t.Fatal(`nextCronRun("0 0 * * *") returned zero`)
		}
		if next.Hour() != 0 || next.Minute() != 0 {
			t.Fatalf("next run = %v, want 00:00", next)
		}
	})

	t.Run("impossible dom with unrestricted dow still yields nothing", func(t *testing.T) {
		// February 31 never occurs and "*" does not rescue it, so this stays
		// invalid — the OR must not turn every unmatched expression into a
		// valid schedule.
		if next := nextCronRun("0 0 31 2 *"); !next.IsZero() {
			t.Fatalf(`nextCronRun("0 0 31 2 *") = %v, want the zero time (no such date)`, next)
		}
	})
}
