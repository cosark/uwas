package backup

import (
	"testing"
	"time"
)

// F3210: a reload whose schedule/cron does not parse must not silently stop
// the schedule that is running (startup ignores it; reload used to stop it).
func TestApplyScheduleInvalidKeepsRunning(t *testing.T) {
	m, _ := scheduledManager(t)
	m.ScheduleBackup(time.Hour)

	// Control: an explicit removal still stops it.
	m.ApplySchedule("", "")
	if _, active := m.ScheduleStatus(); active {
		t.Fatal("control: empty schedule should stop the scheduler")
	}

	for _, c := range []struct{ name, cron, sched string }{
		{"bad-interval", "", "bogus"},
		{"negative-interval", "", "-5m"},
		{"bad-cron", "not a cron", ""},
		{"impossible-cron", "0 0 31 2 *", ""},
	} {
		m.ScheduleBackup(time.Hour)
		m.ApplySchedule(c.cron, c.sched)
		if interval, active := m.ScheduleStatus(); !active || interval != time.Hour {
			t.Errorf("%s: status = %v,%v, want the running 1h schedule kept", c.name, interval, active)
		}
	}
}
