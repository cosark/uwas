package server

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F12900: bandwidth is accounted for the vhost that served the request. The
// manager keys configured host text, so a domain configured in Unicode that a
// browser reaches by its punycode name (or an alias, a wildcard subdomain, a
// differently spelled Host) used to record nothing and its limit never engaged.
func TestBandwidthCountedForServingDomainWhateverHostSpelling(t *testing.T) {
	root := func() string {
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, "index.html"), []byte("0123456789abcdef"), 0o644); err != nil {
			t.Fatal(err)
		}
		return d
	}
	bw := config.BandwidthConfig{Enabled: true, MonthlyLimit: 1 << 20, Action: "block"}
	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{
			{Host: "ascii.example.com", Root: root(), Type: "static", SSL: config.SSLConfig{Mode: "off"}, Bandwidth: bw},
			{Host: "bücher.example", Root: root(), Type: "static", SSL: config.SSLConfig{Mode: "off"}, Bandwidth: bw},
			{Host: "*.wild.example.org", Root: root(), Type: "static", SSL: config.SSLConfig{Mode: "off"}, Bandwidth: bw},
		},
	}
	s := New(cfg, logger.New("error", "text"))
	s.handler = s.buildMiddlewareChain()
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })

	get := func(host string) {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = host
		req.RemoteAddr = "198.51.100.7:1"
		req.Header.Set("User-Agent", "uwas-test")
		s.handler.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("Host %q: status %d, want 200", host, rec.Code)
		}
	}
	used := func(key string) int64 {
		if st := s.bwMgr.GetStatus(key); st != nil {
			return st.MonthlyBytes
		}
		return -1
	}

	cases := []struct {
		name  string
		hosts []string
		key   string
	}{
		{"ascii control", []string{"ascii.example.com", "ASCII.example.com:80"}, "ascii.example.com"},
		{"unicode domain by punycode", []string{"xn--bcher-kva.example"}, "bücher.example"},
		{"unicode domain by unicode host", []string{"bücher.example"}, "bücher.example"},
		{"wildcard subdomain", []string{"one.wild.example.org"}, "*.wild.example.org"},
	}
	for _, c := range cases {
		before := used(c.key)
		if before < 0 {
			t.Fatalf("%s: no usage record for %q", c.name, c.key)
		}
		for _, h := range c.hosts {
			get(h)
		}
		if got := used(c.key) - before; got <= 0 {
			t.Errorf("%s: %v served but %q was accounted %d bytes", c.name, c.hosts, c.key, got)
		}
	}
}
