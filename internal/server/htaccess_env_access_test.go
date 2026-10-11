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

// F6700: SetEnvIf/BrowserMatch drive "Deny from env=" / "Require [not] env";
// the server passes the request so a good client is no longer refused.
func htEnvServer(t *testing.T, sites map[string]string) *Server {
	t.Helper()
	var doms []config.Domain
	for host, ht := range sites {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "page.txt"), []byte("PAGE-BODY"), 0o644)
		os.WriteFile(filepath.Join(dir, ".htaccess"), []byte(ht), 0o644)
		doms = append(doms, config.Domain{Host: host, Type: "static", Root: dir,
			SSL: config.SSLConfig{Mode: "off"}, Htaccess: config.HtaccessConfig{Mode: "import"}})
	}
	cfg := &config.Config{Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"}, Domains: doms}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	return s
}

func htEnvGet(s *Server, host, ip, ua string) int {
	req := httptest.NewRequest(http.MethodGet, "/page.txt", nil)
	req.Host = host
	req.RemoteAddr = ip + ":1"
	req.Header.Set("User-Agent", ua)
	rr := httptest.NewRecorder()
	s.handler.ServeHTTP(rr, req)
	return rr.Code
}

func TestHtaccessEnvConditionsDecidedPerRequest(t *testing.T) {
	s := htEnvServer(t, map[string]string{
		"ua.test":  "SetEnvIf User-Agent \"BadBot\" bad_bot\nOrder Allow,Deny\nAllow from all\nDeny from env=bad_bot\n",
		"req.test": "SetEnvIf Remote_Addr \"^198\\.51\\.100\\.\" office\nRequire env office\n",
		"not.test": "BrowserMatch \"Evil\" evil\n<RequireAll>\nRequire all granted\nRequire not env evil\n</RequireAll>\n",
		"ip.test":  "Order Allow,Deny\nAllow from all\nDeny from 203.0.113.9\n",
	})
	// control: plain IP deny works.
	if c1, c2 := htEnvGet(s, "ip.test", "203.0.113.9", "Mozilla"), htEnvGet(s, "ip.test", "198.51.100.7", "Mozilla"); c1 != 403 || c2 != 200 {
		t.Fatalf("control broken: denied ip=%d (want 403) other ip=%d (want 200)", c1, c2)
	}
	cases := []struct {
		name, host, ip, ua string
		want               int
	}{
		{"Deny from env=: good UA", "ua.test", "198.51.100.7", "Mozilla/5.0", 200},
		{"Deny from env=: bad UA", "ua.test", "198.51.100.7", "BadBot/1.0", 403},
		{"Require env: matching client", "req.test", "198.51.100.7", "Mozilla", 200},
		{"Require env: other client", "req.test", "203.0.113.9", "Mozilla", 403},
		{"Require not env: good UA", "not.test", "198.51.100.7", "Mozilla", 200},
		{"Require not env: Evil UA", "not.test", "198.51.100.7", "EvilScanner", 403},
	}
	for _, c := range cases {
		got := htEnvGet(s, c.host, c.ip, c.ua)
		if got != c.want {
			t.Errorf("%s: status %d, want %d", c.name, got, c.want)
		}
	}
}
