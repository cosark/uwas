package server

import (
	"net/http"

	"github.com/uwaserver/uwas/internal/config"
	proxyhandler "github.com/uwaserver/uwas/internal/handler/proxy"
	"github.com/uwaserver/uwas/internal/middleware"
	"github.com/uwaserver/uwas/internal/rewrite"
)

// domainGuards groups the five per-domain security guards that are all looked
// up via routeMu on every request. By snapshotting them in a single RLock
// we collapse 5 separate lock acquisitions to 1 per request.
type domainGuards struct {
	waf       func(http.ResponseWriter, *http.Request) bool
	ipACL     func(http.ResponseWriter, *http.Request) bool
	geo       func(http.ResponseWriter, *http.Request) bool
	cors      func(http.ResponseWriter, *http.Request) bool
	rateLimit *middleware.RateLimiter
}

// guardsFor returns all per-domain security guards for the given host in a
// single routeMu.RLock/RUnlock pair. Use this instead of calling the
// individual *For accessors when you need more than one guard per request.
func (s *Server) guardsFor(host string) domainGuards {
	s.routeMu.RLock()
	defer s.routeMu.RUnlock()
	return domainGuards{
		waf:       s.wafGuards[host],
		ipACL:     s.ipACLGuards[host],
		geo:       s.geoGuards[host],
		cors:      s.corsGuards[host],
		rateLimit: s.domainRateLimiters[host],
	}
}

func (s *Server) wafGuardFor(host string) func(http.ResponseWriter, *http.Request) bool {
	s.routeMu.RLock()
	defer s.routeMu.RUnlock()
	return s.wafGuards[host]
}

func (s *Server) ipACLGuardFor(host string) func(http.ResponseWriter, *http.Request) bool {
	s.routeMu.RLock()
	defer s.routeMu.RUnlock()
	return s.ipACLGuards[host]
}

func (s *Server) geoGuardFor(host string) func(http.ResponseWriter, *http.Request) bool {
	s.routeMu.RLock()
	defer s.routeMu.RUnlock()
	return s.geoGuards[host]
}

func (s *Server) corsGuardFor(host string) func(http.ResponseWriter, *http.Request) bool {
	s.routeMu.RLock()
	defer s.routeMu.RUnlock()
	return s.corsGuards[host]
}

func (s *Server) rateLimiterFor(host string) *middleware.RateLimiter {
	s.routeMu.RLock()
	defer s.routeMu.RUnlock()
	return s.domainRateLimiters[host]
}

func (s *Server) imageOptChainFor(host string) (middleware.Middleware, bool) {
	s.routeMu.RLock()
	defer s.routeMu.RUnlock()
	m, ok := s.imageOptChains[host]
	return m, ok
}

func (s *Server) rewriteEngineFor(host string) *rewrite.Engine {
	s.routeMu.RLock()
	defer s.routeMu.RUnlock()
	return s.rewriteCache[host]
}

func (s *Server) proxyRouteFor(host string) (*proxyhandler.UpstreamPool, proxyhandler.Balancer, *proxyhandler.CircuitBreaker, *proxyhandler.Mirror, *proxyhandler.CanaryRouter) {
	s.routeMu.RLock()
	defer s.routeMu.RUnlock()
	return s.proxyPools[host], s.proxyBalancers[host], s.proxyBreakers[host], s.proxyMirrors[host], s.proxyCanaries[host]
}

// rebuildProxyPools regenerates proxy pools, balancers, and health
// checkers from the given domains slice. Used by both reload() (after
// reading config from disk) and onDomainChange (after admin API mutates
// in-memory config, BEFORE persistConfig runs). Operates purely on the
// passed slice so it works regardless of whether the caller has
// committed to disk yet.
//
// `apps://<name>` upstreams are resolved here via resolveAppsUpstream,
// so the pool gets a concrete `http://127.0.0.1:<port>` (or the 0-port
// placeholder if the app is currently down). Re-resolution requires
// calling this method again — typically via onDomainChange or reload
// when an app state changes.
func (s *Server) rebuildProxyPools(domains []config.Domain) {
	s.proxy.ResetTransports()

	newPools := make(map[string]*proxyhandler.UpstreamPool)
	newBalancers := make(map[string]proxyhandler.Balancer)
	newHealthChks := make(map[string]*proxyhandler.HealthChecker)
	newBreakers := make(map[string]*proxyhandler.CircuitBreaker)
	newCanaries := make(map[string]*proxyhandler.CanaryRouter)
	newMirrors := make(map[string]*proxyhandler.Mirror)

	// The pools are rebuilt on every reload and domain change; without carrying
	// the old backends' state over, a backend that was down or being drained
	// came back healthy until the next health probe (F10800).
	s.routeMu.RLock()
	oldPools := s.proxyPools
	oldBreakers := s.proxyBreakers
	s.routeMu.RUnlock()

	for _, d := range domains {
		if d.Type != "proxy" || len(d.Proxy.Upstreams) == 0 {
			continue
		}
		var ups []proxyhandler.UpstreamConfig
		for _, u := range d.Proxy.Upstreams {
			ups = append(ups, proxyhandler.UpstreamConfig{
				Address: s.resolveAppsUpstream(u.Address),
				Weight:  u.Weight,
			})
		}
		newPools[d.Host] = proxyhandler.NewUpstreamPool(ups)
		carryBackendState(oldPools[d.Host], newPools[d.Host])
		newBalancers[d.Host] = proxyhandler.NewBalancerFor(d.Proxy, s.logger)

		if d.Proxy.HealthCheck.Path != "" {
			hc := proxyhandler.NewHealthChecker(newPools[d.Host], proxyhandler.HealthConfig{
				Path:               d.Proxy.HealthCheck.Path,
				Interval:           d.Proxy.HealthCheck.Interval.Duration,
				Timeout:            d.Proxy.HealthCheck.Timeout.Duration,
				Threshold:          d.Proxy.HealthCheck.Threshold,
				Rise:               d.Proxy.HealthCheck.Rise,
				AllowPrivate:       d.Proxy.AllowPrivateUpstreams,
				InsecureSkipVerify: d.Proxy.InsecureSkipVerify,
			}, s.logger)
			hc.Start(s.ctx)
			newHealthChks[d.Host] = hc
		}

		// Rebuild circuit breaker / canary / mirror too, so an admin add/remove
		// of a proxy domain doesn't leave a new domain without them or keep a
		// stale breaker after its upstreams changed.
		if d.Proxy.CircuitBreaker.Threshold > 0 {
			nb := proxyhandler.NewCircuitBreaker(
				d.Proxy.CircuitBreaker.Threshold,
				d.Proxy.CircuitBreaker.Timeout.Duration,
			)
			// An open breaker must survive an unrelated rebuild: starting
			// closed let every request in flight hit the failing upstream
			// again (F10801). It restarts only when the upstreams or the
			// breaker settings really changed.
			if ob := oldBreakers[d.Host]; ob != nil && samePoolURLs(oldPools[d.Host], newPools[d.Host]) {
				ot, oto := ob.Params()
				nt, nto := nb.Params()
				if ot == nt && oto == nto {
					nb = ob
				}
			}
			newBreakers[d.Host] = nb
		}
		if d.Proxy.Canary.Enabled && len(d.Proxy.Canary.Upstreams) > 0 {
			newCanaries[d.Host] = proxyhandler.NewCanaryRouter(d.Proxy.Canary, d.Proxy.Algorithm, s.logger)
		}
		if d.Proxy.Mirror.Enabled && d.Proxy.Mirror.Backend != "" {
			newMirrors[d.Host] = proxyhandler.NewMirror(proxyhandler.MirrorConfig{
				Enabled:               d.Proxy.Mirror.Enabled,
				Backend:               d.Proxy.Mirror.Backend,
				Percent:               d.Proxy.Mirror.Percent,
				MaxBodyBytes:          d.Proxy.Mirror.MaxBodyBytes,
				AllowPrivateUpstreams: d.Proxy.AllowPrivateUpstreams,
			}, s.logger)
		}
	}

	// Swap under routeMu, then stop the old health checkers outside the lock so
	// we don't leak goroutines (and don't race two concurrent rebuilds).
	s.routeMu.Lock()
	oldHealthChks := s.proxyHealthChks
	s.proxyPools = newPools
	s.proxyBalancers = newBalancers
	s.proxyHealthChks = newHealthChks
	s.proxyBreakers = newBreakers
	s.proxyCanaries = newCanaries
	s.proxyMirrors = newMirrors
	s.routeMu.Unlock()

	for _, hc := range oldHealthChks {
		hc.Stop()
	}
}

// carryBackendState copies the health/drain state of backends that survive a
// pool rebuild (same upstream URL) from the old pool to the new one.
func carryBackendState(old, fresh *proxyhandler.UpstreamPool) {
	if old == nil || fresh == nil {
		return
	}
	prev := make(map[string]proxyhandler.BackendState)
	for _, b := range old.All() {
		prev[b.URL.String()] = b.GetState()
	}
	for _, b := range fresh.All() {
		if st, ok := prev[b.URL.String()]; ok {
			b.SetState(st)
		}
	}
}

// samePoolURLs reports whether two pools hold exactly the same upstream URLs.
func samePoolURLs(a, b *proxyhandler.UpstreamPool) bool {
	if a == nil || b == nil {
		return false
	}
	have := make(map[string]int)
	for _, x := range a.All() {
		have[x.URL.String()]++
	}
	for _, x := range b.All() {
		have[x.URL.String()]--
	}
	for _, n := range have {
		if n != 0 {
			return false
		}
	}
	return true
}
