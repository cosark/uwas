package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F14703: the proxy transports left MaxResponseHeaderBytes at net/http's 10 MiB
// default, so an upstream could make each response carry megabytes of headers
// that the proxy parsed and forwarded. The header block of an upstream response
// is held to 1 MiB, as the request side is.
func TestProxyRefusesOversizedUpstreamHeaders(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/big"):
			w.Header().Set("X-Big", strings.Repeat("a", 4<<20))
		case strings.HasSuffix(r.URL.Path, "/medium"):
			w.Header().Set("X-Medium", strings.Repeat("a", 256<<10))
		}
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(origin.Close)

	check := func(t *testing.T, get func(path string) *httptest.ResponseRecorder, prefix string) {
		t.Helper()
		if rec := get(prefix + "/plain"); rec.Code != http.StatusOK {
			t.Fatalf("control: status %d", rec.Code)
		}
		if rec := get(prefix + "/medium"); rec.Code != http.StatusOK || len(rec.Header().Get("X-Medium")) != 256<<10 {
			t.Errorf("a 256 KiB header was not forwarded: status %d, %d bytes", rec.Code, len(rec.Header().Get("X-Medium")))
		}
		if rec := get(prefix + "/big"); rec.Code != http.StatusBadGateway || rec.Header().Get("X-Big") != "" {
			t.Errorf("a 4 MiB upstream header: status %d, %d bytes forwarded, want 502 and none", rec.Code, len(rec.Header().Get("X-Big")))
		}
	}

	t.Run("domain proxy", func(t *testing.T) {
		cfg := &config.Config{
			Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
			Domains: []config.Domain{{
				Host: "px.test", Type: "proxy", Root: t.TempDir(), SSL: config.SSLConfig{Mode: "off"},
				Proxy: config.ProxyConfig{Upstreams: []config.Upstream{{Address: origin.URL, Weight: 1}}, AllowPrivateUpstreams: true},
			}},
		}
		s := New(cfg, logger.New("error", "text"))
		t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
		s.handler = s.buildMiddlewareChain()
		check(t, func(path string) *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Host = "px.test"
			req.RemoteAddr = "192.0.2.5:1"
			req.Header.Set("User-Agent", "uwas-test")
			rec := httptest.NewRecorder()
			s.handler.ServeHTTP(rec, req)
			return rec
		}, "")
	})

	t.Run("location proxy", func(t *testing.T) {
		s := locationProxyFixture(t, origin.URL)
		check(t, func(path string) *httptest.ResponseRecorder {
			return locationGet(s, http.MethodGet, path, nil)
		}, "/api")
	})
}
