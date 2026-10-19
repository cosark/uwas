package cronjob

import (
	"fmt"
	"testing"
)

// F22900: SuccessCount/FailureCount cover the whole retained history. The scan
// used to stop at the first success that followed a failure, so a job with a
// long green history and one recent failure reported "1 ok".
func TestStatusCountsCoverWholeHistory(t *testing.T) {
	record := func(m *Monitor, id string, ok bool) {
		m.RecordExecution(ExecutionRecord{ID: id, Domain: "d.com", Command: "cmd", Schedule: "* * * * *", Success: ok})
	}
	check := func(t *testing.T, m *Monitor, ok, fail, streak int) {
		t.Helper()
		st := m.GetStatus("d.com", "cmd")
		if st.SuccessCount != ok || st.FailureCount != fail || st.ConsecutiveFail != streak {
			t.Errorf("GetStatus ok=%d fail=%d streak=%d, want %d/%d/%d", st.SuccessCount, st.FailureCount, st.ConsecutiveFail, ok, fail, streak)
		}
		all := m.GetAllStatus()
		if len(all) != 1 || all[0].SuccessCount != ok || all[0].FailureCount != fail || all[0].ConsecutiveFail != streak {
			t.Errorf("GetAllStatus = %+v, want %d/%d/%d", all, ok, fail, streak)
		}
	}

	t.Run("failure after long green history", func(t *testing.T) {
		m := NewMonitor("")
		for i := 0; i < 5; i++ {
			record(m, fmt.Sprintf("s%d", i), true)
		}
		record(m, "f", false)
		check(t, m, 5, 1, 1)
	})
	t.Run("interleaved", func(t *testing.T) {
		m := NewMonitor("")
		for i, ok := range []bool{true, true, true, true, true, false, true, false} {
			record(m, fmt.Sprintf("r%d", i), ok)
		}
		check(t, m, 6, 2, 1)
	})
	t.Run("all failures", func(t *testing.T) {
		m := NewMonitor("")
		for i := 0; i < 4; i++ {
			record(m, fmt.Sprintf("f%d", i), false)
		}
		check(t, m, 0, 4, 4)
	})
	t.Run("success ends the streak but older failures still count", func(t *testing.T) {
		m := NewMonitor("")
		for i, ok := range []bool{false, false, false, true} {
			record(m, fmt.Sprintf("r%d", i), ok)
		}
		check(t, m, 1, 3, 0)
	})
	t.Run("repeated call is stable and last records are the newest", func(t *testing.T) {
		m := NewMonitor("")
		for i, ok := range []bool{true, false, true, false} {
			record(m, fmt.Sprintf("r%d", i), ok)
		}
		for n := 0; n < 3; n++ {
			check(t, m, 2, 2, 1)
		}
		st := m.GetStatus("d.com", "cmd")
		if st.LastRun.ID != "r3" || st.LastSuccess.ID != "r2" || st.LastFailure.ID != "r3" {
			t.Errorf("last run/success/failure = %s/%s/%s, want r3/r2/r3", st.LastRun.ID, st.LastSuccess.ID, st.LastFailure.ID)
		}
	})
	t.Run("counts follow the retained window", func(t *testing.T) {
		m := NewMonitor("")
		for i := 0; i < m.maxHistory+10; i++ {
			record(m, fmt.Sprintf("r%d", i), i%2 == 0)
		}
		st := m.GetStatus("d.com", "cmd")
		if st.SuccessCount+st.FailureCount != m.maxHistory {
			t.Errorf("ok+fail = %d, want %d", st.SuccessCount+st.FailureCount, m.maxHistory)
		}
	})
}
