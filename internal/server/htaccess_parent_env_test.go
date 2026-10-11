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

// F7000: SetEnvIf in a parent .htaccess must be visible to "Deny from env="
// in a subdirectory's .htaccess (Apache merges per-directory env).
func TestHtaccessParentEnvVisibleToChildDirectory(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "priv"), 0o755)
	os.WriteFile(filepath.Join(dir, "page.txt"), []byte("ROOT"), 0o644)
	os.WriteFile(filepath.Join(dir, "priv", "page.txt"), []byte("PRIV"), 0o644)
	os.WriteFile(filepath.Join(dir, ".htaccess"), []byte("SetEnvIf User-Agent \"BadBot\" bad_bot\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "priv", ".htaccess"), []byte("Order Allow,Deny\nAllow from all\nDeny from env=bad_bot\n"), 0o644)
	same := t.TempDir()
	os.WriteFile(filepath.Join(same, "page.txt"), []byte("SAME"), 0o644)
	os.WriteFile(filepath.Join(same, ".htaccess"), []byte("SetEnvIf User-Agent \"BadBot\" bad_bot\nOrder Allow,Deny\nAllow from all\nDeny from env=bad_bot\n"), 0o644)

	cfg := &config.Config{Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{
			{Host: "x.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"}, Htaccess: config.HtaccessConfig{Mode: "import"}},
			{Host: "same.test", Type: "static", Root: same, SSL: config.SSLConfig{Mode: "off"}, Htaccess: config.HtaccessConfig{Mode: "import"}},
		}}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	get := func(host, path, ua string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = host
		req.RemoteAddr = "198.51.100.7:1"
		req.Header.Set("User-Agent", ua)
		rr := httptest.NewRecorder()
		s.handler.ServeHTTP(rr, req)
		return rr.Code
	}
	// controls: same-file env works; a good UA is served in the subdirectory.
	if c := get("same.test", "/page.txt", "BadBot/1"); c != 403 {
		t.Fatalf("control same-file env: %d want 403", c)
	}
	if c := get("x.test", "/priv/page.txt", "Mozilla/5.0"); c != 200 {
		t.Fatalf("control good UA in subdir: %d want 200", c)
	}
	got := get("x.test", "/priv/page.txt", "BadBot/1")
	if got != 403 {
		t.Errorf("/priv/page.txt with BadBot: got %d, want 403 (parent SetEnvIf visible to child Deny from env=)", got)
	}
}
