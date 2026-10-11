package autoblock

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/logger"
)

func stateFileWith(t *testing.T, ips ...string) []byte {
	t.Helper()
	st := persisted{Saved: time.Now(), History: map[string]int{"203.0.113.77": 2}}
	for _, ip := range ips {
		st.Blocks = append(st.Blocks, Entry{
			IP: ip, Reason: "conn_flood", Hits: 5, Level: 1,
			BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		})
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func loadStateFile(t *testing.T, data []byte) (*Blocker, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "autoblock.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	lg := &logger.Logger{Logger: slog.New(slog.NewTextHandler(&buf, nil))}
	return New(Config{Enabled: true, BlockDuration: time.Hour, PersistPath: path}, lg), path, buf.String()
}

// A state file cut off mid-entry (a torn write) used to be dropped without a
// word: every active block was lost and the next save overwrote the file
// (F15300). The complete entries before the damage are kept, the damage is
// logged and a copy of the damaged file is left beside it.
func TestDamagedStateFileKeepsCompleteEntriesAndSaysSo(t *testing.T) {
	good := stateFileWith(t, "203.0.113.1", "203.0.113.2", "203.0.113.3")
	damaged := good[:bytes.Index(good, []byte(`"ip": "203.0.113.3"`))+12]

	b, path, logs := loadStateFile(t, damaged)
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		if !b.BlockedAddr(ip) {
			t.Errorf("%s: complete entry before the damage was not recovered", ip)
		}
	}
	if b.BlockedAddr("203.0.113.3") {
		t.Error("the entry cut off by the damage must not be trusted")
	}
	if !strings.Contains(strings.ToLower(logs), "damaged") || !strings.Contains(logs, path) {
		t.Errorf("no warning naming the file: %q", logs)
	}
	kept, err := os.ReadFile(path + ".corrupt")
	if err != nil || !bytes.Equal(kept, damaged) {
		t.Errorf("damaged copy not kept intact: err=%v", err)
	}
	// The file itself is rewritten from the recovered state, so a second
	// restart does not depend on the damaged copy.
	b2 := New(Config{Enabled: true, BlockDuration: time.Hour, PersistPath: path}, testLogger())
	if !b2.BlockedAddr("203.0.113.1") || !b2.BlockedAddr("203.0.113.2") {
		t.Error("recovered blocks did not survive a second restart")
	}
}

// An intact file and a missing file stay quiet and unchanged.
func TestIntactAndMissingStateFilesStayQuiet(t *testing.T) {
	b, path, logs := loadStateFile(t, stateFileWith(t, "203.0.113.1", "203.0.113.2"))
	if !b.BlockedAddr("203.0.113.1") || !b.BlockedAddr("203.0.113.2") {
		t.Error("intact file not restored")
	}
	if strings.Contains(strings.ToLower(logs), "damaged") {
		t.Errorf("intact file reported as damaged: %q", logs)
	}
	if _, err := os.Stat(path + ".corrupt"); err == nil {
		t.Error("a damaged copy was written for an intact file")
	}

	var buf bytes.Buffer
	lg := &logger.Logger{Logger: slog.New(slog.NewTextHandler(&buf, nil))}
	New(Config{Enabled: true, BlockDuration: time.Hour, PersistPath: filepath.Join(t.TempDir(), "absent.json")}, lg)
	if strings.Contains(strings.ToLower(buf.String()), "damaged") || strings.Contains(buf.String(), "unreadable") {
		t.Errorf("missing file must not warn: %q", buf.String())
	}
}

// Garbage that is not even a JSON object recovers nothing and does not panic.
func TestUnrecoverableStateFileStartsEmptyAndWarns(t *testing.T) {
	b, path, logs := loadStateFile(t, []byte("\x00\x00not json at all"))
	if b.BlockedAddr("203.0.113.1") {
		t.Error("nothing should be restored from garbage")
	}
	if !strings.Contains(strings.ToLower(logs), "damaged") {
		t.Errorf("no warning for an unparsable file: %q", logs)
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Errorf("unparsable file not kept: %v", err)
	}
}
