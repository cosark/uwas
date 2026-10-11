package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

func proveSite2(t *testing.T, host, ht string) *config.Domain {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "uploads"), 0o755)
	os.WriteFile(filepath.Join(dir, "uploads", "shell.php"), []byte("SECRET-PHP-SOURCE"), 0o644)
	os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("ok"), 0o644)
	os.WriteFile(filepath.Join(dir, ".htaccess"), []byte(ht), 0o644)
	return &config.Domain{Host: host, Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"}, Htaccess: config.HtaccessConfig{Mode: "import"}}
}

func TestHtaccessUncompilableForbidRuleFailsClosed(t *testing.T) {
	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{
			*proveSite2(t, "lookahead.test", "RewriteEngine On\nRewriteRule (?<!index)\\.php$ - [F]\n"),
			*proveSite2(t, "plain.test", "RewriteEngine On\nRewriteRule \\.php$ - [F]\n"),
		},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	get := func(host, path string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = host
		req.RemoteAddr = "198.51.100.7:1"
		req.Header.Set("User-Agent", "uwas-test")
		rr := httptest.NewRecorder()
		s.handler.ServeHTTP(rr, req)
		return rr.Code
	}
	if c := get("plain.test", "/uploads/shell.php"); c != 403 {
		t.Fatalf("control invalid: plain [F] rule gave %d, want 403", c)
	}
	got := get("lookahead.test", "/uploads/shell.php")
	fmt.Printf("EXPECTED: not served (403 or fail-closed 500) for /uploads/shell.php under RewriteRule (?<!index)\\.php$ - [F]\nACTUAL: %d\n", got)
	if got == 200 {
		fmt.Println("PROBLEM CONFIRMED")
		t.FailNow()
	}
	fmt.Println("PROBLEM NOT REPRODUCED")
}
