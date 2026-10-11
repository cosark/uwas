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

// F10500: .htaccess "Deny from" applies to a peer however its address is
// spelled. A zoned link-local peer ("[fe80::1%eth0]:1") is rejected by
// net.ParseIP, so no IP condition matched it and a Deny for fe80::/10 let it in.
func TestHtaccessDenyAppliesToZonedAndMappedPeers(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "page.txt"), []byte("PAGE"), 0o644)
	os.WriteFile(filepath.Join(dir, ".htaccess"),
		[]byte("Order Allow,Deny\nAllow from all\nDeny from 203.0.113.9\nDeny from fe80::/10\n"), 0o644)
	cfg := &config.Config{Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{{Host: "d.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"}}}}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	get := func(remote string) int {
		req := httptest.NewRequest(http.MethodGet, "/page.txt", nil)
		req.Host = "d.test"
		req.RemoteAddr = remote
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec.Code
	}
	for _, c := range []struct {
		remote string
		want   int
	}{
		{"198.51.100.1:1", 200},
		{"[2001:db8::1]:1", 200},
		{"203.0.113.9:1", 403},
		{"[::ffff:203.0.113.9]:1", 403},
		{"[fe80::1]:1", 403},
		{"[fe80::1%eth0]:1", 403},
	} {
		if got := get(c.remote); got != c.want {
			t.Errorf("peer %s: status %d, want %d", c.remote, got, c.want)
		}
	}
}

func TestNormalizedRemoteIPDropsZone(t *testing.T) {
	for in, want := range map[string]string{
		"[fe80::1%eth0]:5000": "fe80::1",
		"[2001:db8::1]:80":    "2001:db8::1",
		"192.0.2.1:80":        "192.0.2.1",
		"fe80::2%lo":          "fe80::2",
		"":                    "",
	} {
		r := &http.Request{RemoteAddr: in}
		if got := normalizedRemoteIP(r); got != want {
			t.Errorf("normalizedRemoteIP(%q) = %q, want %q", in, got, want)
		}
	}
}
