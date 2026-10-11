package admin

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/uwaserver/uwas/internal/auth"
	"github.com/uwaserver/uwas/internal/config"
)

// F7700: a multipart upload was parsed with a 100 MiB in-memory budget, so every
// concurrent upload by a reseller/user could pin its whole body in RAM. Only a
// small budget stays in memory now; the rest is spooled to disk.
func TestFileUploadSpoolsLargeFilesToDisk(t *testing.T) {
	e := newHostConflictEnv(t, []config.Domain{{Host: "site.test", Type: "static"}})
	e.s.configMu.RLock()
	root := e.s.config.Domains[0].Root
	e.s.configMu.RUnlock()

	upload := func(name string, size int) (int, uint64) {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		fw, _ := mw.CreateFormFile("file", name)
		fw.Write(bytes.Repeat([]byte("x"), size))
		mw.WriteField("path", ".")
		mw.Close()
		r := httptest.NewRequest(http.MethodPost, "/api/v1/files/site.test/upload", &body)
		r = r.WithContext(auth.WithUser(r.Context(), &auth.User{ID: "u", Username: "u", Role: auth.RoleReseller, Enabled: true, Domains: []string{"site.test"}}))
		r.Header.Set("Content-Type", mw.FormDataContentType())
		rec := httptest.NewRecorder()
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		e.s.mux.ServeHTTP(rec, r)
		runtime.ReadMemStats(&after)
		return rec.Code, after.TotalAlloc - before.TotalAlloc
	}

	if code, _ := upload("small.bin", 256<<10); code != http.StatusOK {
		t.Fatalf("small upload: code %d", code)
	}
	if fi, err := os.Stat(filepath.Join(root, "small.bin")); err != nil || fi.Size() != 256<<10 {
		t.Fatalf("small upload not stored intact: %v", err)
	}

	const big = 40 << 20
	code, alloc := upload("big.bin", big)
	if code != http.StatusOK {
		t.Fatalf("big upload: code %d", code)
	}
	if fi, err := os.Stat(filepath.Join(root, "big.bin")); err != nil || fi.Size() != big {
		t.Fatalf("big upload not stored intact: %v", err)
	}
	// Buffering the body costs 3x+ the file size (128 MiB; 256 MiB under -race);
	// spooling stays within 2x even with the race detector.
	if alloc >= 2*big {
		t.Errorf("a %d MiB upload allocated %d MiB; want it spooled to disk", big>>20, alloc>>20)
	}

	// The per-file cap is unchanged: an oversized file is refused and not written.
	if code, _ := upload("huge.bin", 51<<20); code != http.StatusBadRequest {
		t.Errorf("51 MiB upload: code %d, want 400", code)
	}
	if _, err := os.Stat(filepath.Join(root, "huge.bin")); err == nil {
		t.Error("oversized upload was written")
	}
}
