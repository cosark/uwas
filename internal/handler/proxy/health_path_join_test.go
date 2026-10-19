package proxy

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/uwaserver/uwas/internal/logger"
)

// pathRT answers every probe 200 and records the paths it was asked for.
type pathRT struct {
	mu    sync.Mutex
	paths []string
}

func (p *pathRT) RoundTrip(req *http.Request) (*http.Response, error) {
	p.mu.Lock()
	p.paths = append(p.paths, req.URL.RequestURI())
	p.mu.Unlock()
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}

// The probe URL is the backend address joined with health_check.path. A path
// written without its leading slash ("health") glued onto "host:port" made an
// unparseable URL, so every probe failed and the backend was marked unhealthy
// even though it was fine; a backend address with a trailing slash probed
// "//health" instead of "/health" (F20200).
func TestHealthProbeURLJoin(t *testing.T) {
	probe := func(addr, path string) ([]string, *Backend) {
		pool := NewUpstreamPool([]UpstreamConfig{{Address: addr, Weight: 1}})
		hc := NewHealthChecker(pool, HealthConfig{Path: path, Threshold: 1, Rise: 1, AllowPrivate: true}, logger.New("error", "text"))
		rt := &pathRT{}
		hc.client.Transport = rt
		b := pool.All()[0]
		hc.checkOne(b)
		return rt.paths, b
	}

	cases := []struct {
		name, addr, path, want string
	}{
		{"control", "http://127.0.0.1:8081", "/health", "/health"},
		{"control-base-path", "http://127.0.0.1:8081/app", "/health", "/app/health"},
		{"control-query", "http://127.0.0.1:8081", "/health?deep=1", "/health?deep=1"},
		{"no-leading-slash", "http://127.0.0.1:8081", "health", "/health"},
		{"trailing-slash-backend", "http://127.0.0.1:8081/", "/health", "/health"},
	}
	failed := false
	for _, tc := range cases {
		got, b := probe(tc.addr, tc.path)
		actual := "<no probe sent>"
		if len(got) == 1 {
			actual = got[0]
		}
		t.Logf("%s: EXPECTED: %s (healthy) ACTUAL: %s (healthy=%v)", tc.name, tc.want, actual, b.IsHealthy())
		if actual != tc.want || !b.IsHealthy() {
			failed = true
			t.Errorf("%s: probe path = %q healthy=%v, want %q healthy", tc.name, actual, b.IsHealthy(), tc.want)
		}
	}
	if failed {
		t.Log("PROBLEM CONFIRMED")
	} else {
		t.Log("PROBLEM NOT REPRODUCED")
	}
}
