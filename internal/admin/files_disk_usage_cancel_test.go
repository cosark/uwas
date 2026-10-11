package admin

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// F14901: the disk-usage route answers a live request and writes nothing for a
// request whose client has already gone.
func TestFilesDiskUsageHonoursRequestContext(t *testing.T) {
	s, root := testServerWithRoot(t)
	for i := 0; i < 20; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("f%02d", i)), []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	call := func(ctx context.Context) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/v1/files/example.com/disk-usage", nil).WithContext(ctx)
		req.SetPathValue("domain", "example.com")
		s.handleDiskUsage(rec, req)
		return rec
	}
	if rec := call(context.Background()); rec.Code != 200 || rec.Body.Len() == 0 {
		t.Fatalf("live request: status %d, body %q", rec.Code, rec.Body.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rec := call(ctx); rec.Body.Len() != 0 {
		t.Errorf("cancelled request still produced a body: %q", rec.Body.String())
	}
}
