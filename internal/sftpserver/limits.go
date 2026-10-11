package sftpserver

import (
	"net"
	"net/netip"
	"sync"
)

// Connection limits (F15200, F15201). The SFTP listener lives in the process
// that also serves HTTP, so connections it holds compete with the web server
// for file descriptors, and each password attempt costs a cost-14 bcrypt
// compare. x/crypto/ssh limits neither the number of unauthenticated
// connections nor the number of channels an authenticated client opens.
//
// A zero Config value selects these defaults.
const (
	// defaultMaxHandshakes bounds connections that have not finished the SSH
	// handshake (and so are not yet authenticated), across all clients. It is
	// the counterpart of OpenSSH's MaxStartups: a connection that completes or
	// fails its handshake gives the slot back at once, so ordinary traffic
	// never gets near it.
	defaultMaxHandshakes = 128

	// defaultMaxHandshakesPerSource keeps one source from taking every slot.
	// IPv6 sources are counted per /64, the unit a single customer controls.
	defaultMaxHandshakesPerSource = 32

	// defaultMaxSessionsPerConn bounds the session channels one authenticated
	// connection holds open, as OpenSSH's MaxSessions does (default 10). Every
	// accepted channel starts a goroutine and allocates buffers.
	defaultMaxSessionsPerConn = 10
)

func orDefault(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

func (s *Server) maxSessionsPerConn() int {
	return orDefault(s.config.MaxSessionsPerConn, defaultMaxSessionsPerConn)
}

// handshakeGate counts connections currently in the SSH handshake.
type handshakeGate struct {
	mu     sync.Mutex
	total  int
	source map[string]int
}

// sourceKey groups a peer address: IPv6 by /64, everything else by host. ok is
// false for an address that is not an IP (a test pipe), which is only counted
// against the global limit.
func sourceKey(a net.Addr) (key string, ok bool) {
	if a == nil {
		return "", false
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return "", false
	}
	ip := ap.Addr().Unmap().WithZone("")
	if ip.Is6() {
		return netip.PrefixFrom(ip, 64).Masked().String(), true
	}
	return ip.String(), true
}

// enter admits a connection to the handshake phase, or reports false when the
// global or per-source limit is reached. The returned release function gives
// the slot back and is safe to call more than once.
func (g *handshakeGate) enter(a net.Addr, maxTotal, maxPerSource int) (release func(), ok bool) {
	key, keyed := sourceKey(a)

	g.mu.Lock()
	if g.total >= maxTotal || (keyed && g.source[key] >= maxPerSource) {
		g.mu.Unlock()
		return nil, false
	}
	g.total++
	if keyed {
		if g.source == nil {
			g.source = make(map[string]int)
		}
		g.source[key]++
	}
	g.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			g.total--
			if keyed {
				if g.source[key]--; g.source[key] <= 0 {
					delete(g.source, key)
				}
			}
			g.mu.Unlock()
		})
	}, true
}
