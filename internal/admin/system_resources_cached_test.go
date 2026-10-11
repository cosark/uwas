package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
)

// F14603: GET /api/v1/system/resources walked the entire web root (every
// tenant's files) inside each request. The figure now comes from a cache that
// is refreshed once, in the background.
func TestSystemResourcesDiskUsageIsCachedAndRefreshedInBackground(t *testing.T) {
	var calls atomic.Int32
	var gate atomic.Pointer[chan struct{}]
	orig := diskUsageFn
	diskUsageFn = func(string) (int64, error) {
		calls.Add(1)
		if g := gate.Load(); g != nil {
			<-*g
		}
		return 5 << 20, nil
	}
	var servers []*Server
	t.Cleanup(func() {
		// Join every background refresher before the seam is restored.
		deadline := time.Now().Add(5 * time.Second)
		for _, s := range servers {
			for s.diskRefreshing.Load() && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
		}
		diskUsageFn = orig
	})
	newSrv := func() *Server {
		s := testServerFromConfig(t, &config.Config{
			Global: config.GlobalConfig{WebRoot: t.TempDir(), Admin: config.AdminConfig{Listen: "127.0.0.1:0"}},
		})
		servers = append(servers, s)
		return s
	}
	get := func(s *Server) map[string]any {
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/system/resources", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	waitIdle := func(s *Server) {
		t.Helper()
		for i := 0; i < 1000 && s.diskRefreshing.Load(); i++ {
			time.Sleep(5 * time.Millisecond)
		}
		if s.diskRefreshing.Load() {
			t.Fatal("background refresh did not finish")
		}
	}

	// A slow walk must not hold the request.
	release := make(chan struct{})
	gate.Store(&release)
	slow := newSrv()
	done := make(chan struct{})
	go func() { get(slow); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(release)
		<-done
		t.Fatal("the request waited for the web-root walk")
	}
	close(release)
	waitIdle(slow)
	gate.Store(nil)

	// Repeated requests share one walk, and the figure appears once it is done.
	base := calls.Load()
	s := newSrv()
	first := get(s)
	waitIdle(s)
	for i := 0; i < 4; i++ {
		get(s)
	}
	if got := calls.Load() - base; got != 1 {
		t.Fatalf("5 requests started %d web-root walks, want 1", got)
	}
	if _, ok := first["disk_used_bytes"]; ok {
		t.Errorf("the first response cannot carry a figure that has not been measured yet: %v", first["disk_used_bytes"])
	}
	if v, _ := get(s)["disk_used_bytes"].(float64); int64(v) != 5<<20 {
		t.Errorf("disk_used_bytes = %v after the refresh, want %d", v, 5<<20)
	}
}
