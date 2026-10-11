package admin

import (
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
)

// F14004: PUT /api/v1/settings stored global.backup.schedule as typed text. The
// scheduler reads the cron expression first and otherwise parses the field as
// a Go duration, so a day shorthand ("1d", the form the backup page shows), a
// cron expression typed into the field and any interval entered while a cron
// was configured were all saved as "saved" and then never ran (or kept
// running the old cron) after the next start or reload.

// effectiveBackupSchedule mirrors the choice server.Start makes.
func effectiveBackupSchedule(b config.BackupConfig) (cron string, interval time.Duration) {
	if b.Cron != "" {
		return b.Cron, 0
	}
	if d, err := time.ParseDuration(b.Schedule); err == nil && d > 0 {
		return "", d
	}
	return "", 0
}

func TestSettingsPutBackupScheduleIsUsable(t *testing.T) {
	for _, tc := range []struct {
		name       string
		startCron  string
		payload    string
		wantCron   string
		wantEvery  time.Duration
		wantReject bool
	}{
		{"interval (control)", "", `{"global.backup.schedule": "24h"}`, "", 24 * time.Hour, false},
		{"day shorthand from the backup page", "", `{"global.backup.schedule": "1d"}`, "", 24 * time.Hour, false},
		{"three days", "", `{"global.backup.schedule": "3d"}`, "", 72 * time.Hour, false},
		{"cron typed into the field", "", `{"global.backup.schedule": "0 2 * * *"}`, "0 2 * * *", 0, false},
		{"interval replaces a configured cron", "0 3 * * *", `{"global.backup.schedule": "12h"}`, "", 12 * time.Hour, false},
		{"cron replaces a configured interval", "", `{"global.backup.schedule": "30 4 * * 1"}`, "30 4 * * 1", 0, false},
		{"empty switches the schedule off", "0 3 * * *", `{"global.backup.schedule": ""}`, "", 0, false},
		{"words", "", `{"global.backup.schedule": "daily"}`, "", 0, true},
		{"cron with an hour that never occurs", "", `{"global.backup.schedule": "30 25 * * *"}`, "", 0, true},
		{"negative interval", "", `{"global.backup.schedule": "-1h"}`, "", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := settingsTestServer(t)
			s.config.Global.Backup.Schedule = "6h"
			s.config.Global.Backup.Cron = tc.startCron
			code, body := putSettingsStatus(s, tc.payload)
			cron, every := effectiveBackupSchedule(s.config.Global.Backup)
			if tc.wantReject {
				if code != 400 {
					t.Errorf("status = %d body %q, want 400", code, body)
				}
				if s.config.Global.Backup.Schedule != "6h" || s.config.Global.Backup.Cron != tc.startCron {
					t.Errorf("a refused value changed the schedule: %+v", s.config.Global.Backup)
				}
				return
			}
			if code != 200 || cron != tc.wantCron || every != tc.wantEvery {
				t.Errorf("status = %d, effective schedule = cron %q every %v, want cron %q every %v (stored %q / %q)",
					code, cron, every, tc.wantCron, tc.wantEvery, s.config.Global.Backup.Schedule, s.config.Global.Backup.Cron)
			}
		})
	}
}

// The panel saves what GET showed. With a cron configured, GET must show it,
// or saving the page would replace the cron with an empty schedule.
func TestSettingsGetShowsTheEffectiveBackupSchedule(t *testing.T) {
	s := settingsTestServer(t)
	s.config.Global.Backup.Cron = "0 3 * * *"
	s.config.Global.Backup.Schedule = "6h"
	if got := settingsBody(t, s)["global.backup.schedule"]; got != "0 3 * * *" {
		t.Errorf("GET global.backup.schedule = %v, want the cron that runs", got)
	}

	body := settingsBody(t, s)
	payload := `{"global.backup.schedule": "` + body["global.backup.schedule"].(string) + `"}`
	if code, out := putSettingsStatus(s, payload); code != 200 {
		t.Fatalf("saving the page back: status %d %s", code, out)
	}
	if cron, _ := effectiveBackupSchedule(s.config.Global.Backup); cron != "0 3 * * *" {
		t.Errorf("saving the page back changed the schedule: %+v", s.config.Global.Backup)
	}
}
