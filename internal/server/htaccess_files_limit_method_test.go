package server

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F5500: a <Limit> section inside <Files> must apply to the request method
// instead of being dropped by a method-less file check.
func TestHtaccessFilesLimitHonoursRequestMethod(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "wp-config.php"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, ".htaccess"),
		[]byte("<Files wp-config.php>\n<Limit GET POST>\nRequire all denied\n</Limit>\n</Files>\n"), 0o644)

	cfg := &config.Config{Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"}}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })

	ip := net.ParseIP("198.51.100.7")
	target := filepath.Join(dir, "wp-config.php")
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		if d := s.htaccessAccess(dir, target, false, ip, m); d.status != http.StatusForbidden {
			t.Errorf("%s wp-config.php: status %d, want 403", m, d.status)
		}
	}
	other := filepath.Join(dir, "readme.txt")
	if d := s.htaccessAccess(dir, other, false, ip, http.MethodGet); d.status != 0 {
		t.Errorf("control readme.txt: status %d, want allowed", d.status)
	}
}
