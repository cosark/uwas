package apps

// Regression test for F5300: the app Logs endpoint returns only the last
// 100KiB of the log but must not read the whole (append-only, never rotated)
// file into memory to do so.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/uwaserver/uwas/internal/apps"
)

func logsTailSetup(t *testing.T, logName string, content func(f *os.File)) *Handler {
	t.Helper()
	root := t.TempDir()
	work := filepath.Join(root, "work")
	logs := filepath.Join(root, "logs")
	for _, d := range []string{work, logs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mgr := apps.NewManager(apps.NewStore(t.TempDir()), nil)
	a := &apps.App{Name: "big", Runtime: apps.RuntimeCustom, Command: "exec sleep 600", WorkDir: work, Port: 18853, Disabled: true}
	if err := mgr.Register(a); err != nil {
		t.Fatalf("register: %v", err)
	}
	f, err := os.Create(filepath.Join(logs, logName))
	if err != nil {
		t.Fatal(err)
	}
	content(f)
	f.Close()
	return New(&updInvalidDeps{mgr: mgr})
}

func logsTailGet(h *Handler) (map[string]string, int) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/apps/big/logs", nil)
	req.SetPathValue("name", "big")
	rec := httptest.NewRecorder()
	h.Logs(rec, req)
	var out map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out, rec.Code
}

func TestLogsTailIsBoundedAndCorrect(t *testing.T) {
	const size = 32 << 20
	h := logsTailSetup(t, "big.log", func(f *os.File) {
		chunk := bytes.Repeat([]byte("x"), 1<<20)
		for i := 0; i < size>>20; i++ {
			f.Write(chunk)
		}
		f.WriteString("TAIL-MARKER")
	})
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	out, code := logsTailGet(h)
	runtime.ReadMemStats(&after)
	if code != http.StatusOK || out["kind"] != "runtime" {
		t.Fatalf("code=%d out kind=%q", code, out["kind"])
	}
	if got := len(out["log"]); got != logTailBytes {
		t.Errorf("tail length = %d, want %d", got, logTailBytes)
	}
	if !bytes.HasSuffix([]byte(out["log"]), []byte("TAIL-MARKER")) {
		t.Error("tail does not end with the newest log bytes")
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 4<<20 {
		t.Errorf("Logs allocated %d bytes for a %d byte log; want a bounded tail read", alloc, size)
	}
}

func TestLogsSmallAndBuildFallback(t *testing.T) {
	h := logsTailSetup(t, "big.log", func(f *os.File) { f.WriteString("short log\n") })
	if out, _ := logsTailGet(h); out["log"] != "short log\n" || out["kind"] != "runtime" {
		t.Errorf("small log = %q kind=%q", out["log"], out["kind"])
	}
	h = logsTailSetup(t, "big-build.log", func(f *os.File) { f.WriteString("build output") })
	if out, _ := logsTailGet(h); out["log"] != "build output" || out["kind"] != "build" {
		t.Errorf("build fallback = %q kind=%q", out["log"], out["kind"])
	}
	h = logsTailSetup(t, "other.log", func(f *os.File) {})
	if out, _ := logsTailGet(h); out["log"] != "" || out["kind"] != "runtime" {
		t.Errorf("no log = %q kind=%q", out["log"], out["kind"])
	}
}
