package server

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
)

// proxy.insecure_skip_verify applies to the health probe too: a self-signed
// HTTPS upstream the proxy serves must stay healthy (F4500).
func TestHealthProbeHonoursInsecureSkipVerify(t *testing.T) {
	var tlsHits, plainHits atomic.Int32
	tlsUp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { tlsHits.Add(1) }))
	defer tlsUp.Close()
	plainUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { plainHits.Add(1) }))
	defer plainUp.Close()

	s := newDispatchTestServer(t, nil)
	mk := func(host, addr string, skip bool) config.Domain {
		return config.Domain{Host: host, Type: "proxy", SSL: config.SSLConfig{Mode: "off"},
			Proxy: config.ProxyConfig{
				Upstreams: []config.Upstream{{Address: addr, Weight: 1}}, Algorithm: "round_robin",
				AllowPrivateUpstreams: true, InsecureSkipVerify: skip,
				HealthCheck: config.HealthCheckConfig{Path: "/", Interval: config.Duration{Duration: 10 * time.Millisecond},
					Timeout: config.Duration{Duration: time.Second}, Threshold: 1, Rise: 1},
			}}
	}
	s.rebuildProxyPools([]config.Domain{mk("tls.test", tlsUp.URL, true), mk("plain.test", plainUp.URL, false)})

	healthy := func(host string) bool { return s.proxyPools[host].All()[0].IsHealthy() }
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && plainHits.Load() < 3 {
		time.Sleep(5 * time.Millisecond)
	}
	if plainHits.Load() < 3 || !healthy("plain.test") {
		t.Fatalf("control: hits=%d healthy=%v", plainHits.Load(), healthy("plain.test"))
	}
	for time.Now().Before(deadline) && tlsHits.Load() < 3 && healthy("tls.test") {
		time.Sleep(5 * time.Millisecond)
	}
	if tlsHits.Load() < 3 || !healthy("tls.test") {
		t.Fatalf("self-signed upstream with insecure_skip_verify: hits=%d healthy=%v", tlsHits.Load(), healthy("tls.test"))
	}
}
