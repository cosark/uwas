package server

import (
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	proxyhandler "github.com/uwaserver/uwas/internal/handler/proxy"
)

// F10800: every reload and domain change rebuilds the proxy pools; a backend
// that was marked unhealthy or draining must keep that state instead of coming
// back healthy until the next probe.
func TestRebuildProxyPoolsKeepsBackendState(t *testing.T) {
	doms := []config.Domain{{
		Host: "hs.test", Type: "proxy", SSL: config.SSLConfig{Mode: "off"},
		Proxy: config.ProxyConfig{
			Upstreams:             []config.Upstream{{Address: "http://127.0.0.1:1", Weight: 1}, {Address: "http://127.0.0.1:2", Weight: 1}},
			AllowPrivateUpstreams: true,
		},
	}}
	s := newDispatchTestServer(t, doms)
	s.rebuildProxyPools(s.config.Domains)

	state := func(addr string) proxyhandler.BackendState {
		s.routeMu.RLock()
		defer s.routeMu.RUnlock()
		for _, b := range s.proxyPools["hs.test"].All() {
			if b.URL.Host == addr {
				return b.GetState()
			}
		}
		return -1
	}
	s.routeMu.RLock()
	for _, b := range s.proxyPools["hs.test"].All() {
		switch b.URL.Host {
		case "127.0.0.1:1":
			b.SetState(proxyhandler.StateUnhealthy)
		case "127.0.0.1:2":
			b.SetState(proxyhandler.StateDraining)
		}
	}
	s.routeMu.RUnlock()

	s.rebuildProxyPools(s.config.Domains)
	if got := state("127.0.0.1:1"); got != proxyhandler.StateUnhealthy {
		t.Errorf("unhealthy backend state after rebuild = %d, want %d", got, proxyhandler.StateUnhealthy)
	}
	if got := state("127.0.0.1:2"); got != proxyhandler.StateDraining {
		t.Errorf("draining backend state after rebuild = %d, want %d", got, proxyhandler.StateDraining)
	}

	// Control: a backend whose address changed is a new backend and starts healthy.
	s.config.Domains[0].Proxy.Upstreams[0].Address = "http://127.0.0.1:3"
	s.rebuildProxyPools(s.config.Domains)
	if got := state("127.0.0.1:3"); got != proxyhandler.StateHealthy {
		t.Errorf("new backend state = %d, want healthy", got)
	}
	if got := state("127.0.0.1:2"); got != proxyhandler.StateDraining {
		t.Errorf("surviving draining backend lost its state: %d", got)
	}
}

// F10801: an open circuit breaker must stay open across a rebuild that changed
// nothing about its domain, and restart closed when the upstreams change.
func TestRebuildProxyPoolsKeepsOpenCircuitBreaker(t *testing.T) {
	doms := []config.Domain{{
		Host: "br.test", Type: "proxy", SSL: config.SSLConfig{Mode: "off"},
		Proxy: config.ProxyConfig{
			Upstreams:             []config.Upstream{{Address: "http://127.0.0.1:1", Weight: 1}},
			AllowPrivateUpstreams: true,
			CircuitBreaker:        config.CircuitConfig{Threshold: 3, Timeout: config.Duration{Duration: time.Hour}},
		},
	}}
	s := newDispatchTestServer(t, doms)
	s.rebuildProxyPools(s.config.Domains)

	breaker := func() *proxyhandler.CircuitBreaker {
		s.routeMu.RLock()
		defer s.routeMu.RUnlock()
		return s.proxyBreakers["br.test"]
	}
	for i := 0; i < 3; i++ {
		breaker().RecordFailure()
	}
	if breaker().State() != proxyhandler.CircuitOpen {
		t.Fatal("setup: breaker did not open")
	}

	s.rebuildProxyPools(s.config.Domains)
	if b := breaker(); b.State() != proxyhandler.CircuitOpen || b.Allow() {
		t.Errorf("open breaker was reset by an unrelated rebuild (state=%d)", b.State())
	}

	// Changed breaker settings and changed upstreams both start a fresh breaker.
	s.config.Domains[0].Proxy.CircuitBreaker.Threshold = 7
	s.rebuildProxyPools(s.config.Domains)
	if breaker().State() != proxyhandler.CircuitClosed {
		t.Error("breaker with new settings should start closed")
	}
	for i := 0; i < 7; i++ {
		breaker().RecordFailure()
	}
	s.config.Domains[0].Proxy.Upstreams[0].Address = "http://127.0.0.1:2"
	s.rebuildProxyPools(s.config.Domains)
	if breaker().State() != proxyhandler.CircuitClosed {
		t.Error("breaker for a changed upstream should start closed")
	}
}
