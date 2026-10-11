package proxy

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/uwaserver/uwas/internal/logger"
)

type recordingRT struct {
	mu    sync.Mutex
	hosts []string
}

func (r *recordingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.hosts = append(r.hosts, req.URL.Host)
	r.mu.Unlock()
	h := http.Header{}
	status := http.StatusOK
	if req.URL.Host == "127.0.0.1:9" {
		status = http.StatusFound
		h.Set("Location", "http://169.254.169.254/latest/meta-data/")
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}

// The health probe checks only the configured backend against the SSRF
// policy, so it must not follow a redirect to an address that was never
// checked (F3700). A 3xx still counts as an answer from the backend.
func TestHealthProbeDoesNotFollowRedirects(t *testing.T) {
	probe := func(addr string) ([]string, *Backend) {
		pool := NewUpstreamPool([]UpstreamConfig{{Address: addr, Weight: 1}})
		hc := NewHealthChecker(pool, HealthConfig{Path: "/", Threshold: 1, Rise: 1}, logger.New("error", "text"))
		rt := &recordingRT{}
		hc.client.Transport = rt
		b := pool.All()[0]
		hc.checkOne(b)
		return rt.hosts, b
	}

	if got, _ := probe("http://169.254.169.254"); len(got) != 0 {
		t.Fatalf("blocked backend was probed: %v", got)
	}
	if got, _ := probe("http://127.0.0.1:8"); len(got) != 1 {
		t.Fatalf("plain backend probe count = %v, want 1", got)
	}
	got, b := probe("http://127.0.0.1:9")
	if len(got) != 1 {
		t.Fatalf("redirect was followed: contacted %v", got)
	}
	if !b.IsHealthy() {
		t.Fatal("backend answering 302 should stay healthy")
	}
}
