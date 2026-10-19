package backup

import (
	"testing"
	"time"
)

// F22700: a cron schedule replaces the interval ticker, so the manager must not
// keep reporting the replaced interval or derive next_backup from it.
func TestScheduleBackupCronClearsReplacedInterval(t *testing.T) {
	m, _ := scheduledManager(t)
	m.ScheduleBackup(24 * time.Hour)
	m.mu.Lock()
	m.lastBackup = time.Now().UTC()
	m.mu.Unlock()
	if d := m.ScheduleDetail(); d.Interval != "1d" || d.NextBackup == "" {
		t.Fatalf("interval schedule must report itself: interval=%q next=%q", d.Interval, d.NextBackup)
	}

	m.ScheduleBackupCron("0 2 * * *")
	iv, on := m.ScheduleStatus()
	if !on || iv != 0 {
		t.Fatalf("cron schedule: active=%v interval=%v, want active with interval 0", on, iv)
	}
	if d := m.ScheduleDetail(); d.Interval == "1d" || d.NextBackup != "" {
		t.Fatalf("detail still derives from the replaced interval: interval=%q next=%q", d.Interval, d.NextBackup)
	}

	// Cron removed: nothing runs and nothing stale is reported.
	m.ScheduleBackupCron("")
	if iv, on := m.ScheduleStatus(); on || iv != 0 {
		t.Fatalf("after clearing cron: active=%v interval=%v", on, iv)
	}

	// Interval back after a cron: it reports itself again.
	m.ScheduleBackup(time.Hour)
	if iv, on := m.ScheduleStatus(); !on || iv != time.Hour {
		t.Fatalf("interval after cron: active=%v interval=%v", on, iv)
	}
}

// ApplySchedule must still treat an unchanged interval as unchanged after the
// cron path stopped carrying a stale interval.
func TestApplyScheduleIntervalAfterCronRestarts(t *testing.T) {
	m, _ := scheduledManager(t)
	m.ApplySchedule("", "1h")
	m.ApplySchedule("0 2 * * *", "1h")
	if iv, on := m.ScheduleStatus(); !on || iv != 0 {
		t.Fatalf("cron wins over interval: active=%v interval=%v", on, iv)
	}
	m.ApplySchedule("", "1h")
	if iv, on := m.ScheduleStatus(); !on || iv != time.Hour || m.cronExpr != "" {
		t.Fatalf("interval must replace the cron: active=%v interval=%v cron=%q", on, iv, m.cronExpr)
	}
}
