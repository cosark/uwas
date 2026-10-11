package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F4800: a PHP domain only hands files ending in lowercase ".php" to PHP.
// A file named Config.PHP is served as plain static text, disclosing source.
func TestUppercasePHPExtensionNotServedAsSource(t *testing.T) {
	dir := t.TempDir()
	src := "<?php $dbpass = 'SECRETPASS';"
	for _, n := range []string{"conf.php", "Conf.PHP", "Conf.Php"} {
		os.WriteFile(filepath.Join(dir, n), []byte(src), 0o644)
	}
	os.WriteFile(filepath.Join(dir, "index.php"), []byte("<?php echo 1;"), 0o644)
	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{{Host: "php.test", Type: "php", Root: dir, SSL: config.SSLConfig{Mode: "off"},
			PHP: config.PHPConfig{FPMAddress: "127.0.0.1:1"}}},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	get := func(p string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Host = "php.test"
		req.RemoteAddr = "192.0.2.5:1"
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	_, b := get("/conf.php")
	if strings.Contains(b, "SECRETPASS") {
		t.Fatalf("control /conf.php leaks source")
	}
	bad := false
	for _, p := range []string{"/Conf.PHP", "/Conf.Php"} {
		_, b := get(p)
		leak := strings.Contains(b, "SECRETPASS")
		if leak {
			bad = true
		}
	}
	if bad {
		t.Fatal("uppercase .PHP source disclosed")
	}
}
