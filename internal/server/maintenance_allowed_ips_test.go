package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F15900: maintenance allowed_ips was compared as a string against the peer
// address. Only the exact text of an IPv4 address matched; a CIDR range, another
// spelling of an IPv6 address and an IPv4-mapped address never did, and the
// operator the entry was written for was shown the maintenance page.
func TestMaintenanceAllowedIPsAcceptRangesAndSpellings(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("SITE"), 0o644)

	entries := map[string][]string{
		"exact.test":  {"192.0.2.5"},
		"cidr.test":   {"192.0.2.0/24"},
		"v6.test":     {"0:0:0:0:0:0:0:1"},
		"v6cidr.test": {"2001:db8::/32"},
		"mapped.test": {"::ffff:192.0.2.5"},
		"other.test":  {"198.51.100.0/24"},
	}
	var domains []config.Domain
	for host, ips := range entries {
		domains = append(domains, config.Domain{Host: host, Type: "static", Root: dir,
			SSL:         config.SSLConfig{Mode: "off"},
			Maintenance: config.MaintenanceConfig{Enabled: true, AllowedIPs: ips}})
	}
	cfg := &config.Config{Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"}, Domains: domains}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()

	get := func(host, remote string) int {
		req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
		req.Host = host
		req.RemoteAddr = remote
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec.Code
	}
	for _, c := range []struct {
		host, remote string
		want         int
	}{
		{"exact.test", "192.0.2.5:1", 200}, // control: the form that always worked
		{"exact.test", "192.0.2.6:1", 503},
		{"cidr.test", "192.0.2.77:1", 200},
		{"cidr.test", "192.0.3.1:1", 503},
		{"v6.test", "[::1]:1", 200},
		{"v6cidr.test", "[2001:db8:1::9]:1", 200},
		{"v6cidr.test", "[2001:db9::1]:1", 503},
		{"mapped.test", "192.0.2.5:1", 200},
		{"other.test", "192.0.2.5:1", 503},
		{"cidr.test", "[fe80::1%eth0]:1", 503}, // a zoned peer is judged as the address it is
	} {
		if got := get(c.host, c.remote); got != c.want {
			t.Errorf("%s from %s = %d, want %d", c.host, c.remote, got, c.want)
		}
	}
}

func TestMaintenanceAllows(t *testing.T) {
	for _, c := range []struct {
		allowed []string
		client  string
		want    bool
	}{
		{nil, "192.0.2.5", false},
		{[]string{"192.0.2.5"}, "192.0.2.5", true},
		{[]string{"192.0.2.0/24"}, "192.0.2.200", true},
		{[]string{"192.0.2.0/24"}, "192.0.3.1", false},
		{[]string{"::ffff:192.0.2.5"}, "192.0.2.5", true},
		{[]string{"0:0:0:0:0:0:0:1"}, "::1", true},
		{[]string{"not-an-ip", "192.0.2.5"}, "192.0.2.5", true},
		{[]string{"192.0.2.0/24"}, "", false},
		{[]string{"192.0.2.0/24"}, "garbage", false},
	} {
		if got := maintenanceAllows(c.allowed, c.client); got != c.want {
			t.Errorf("maintenanceAllows(%v, %q) = %v, want %v", c.allowed, c.client, got, c.want)
		}
	}
}
