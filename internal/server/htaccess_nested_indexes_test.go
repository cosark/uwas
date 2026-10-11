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

func TestHtaccessNestedIndexesHonoredForListing(t *testing.T) {
	mk := func(rootHt, subHt string) string {
		dir := t.TempDir()
		os.MkdirAll(filepath.Join(dir, "uploads"), 0o755)
		os.WriteFile(filepath.Join(dir, "uploads", "private-name.txt"), []byte("x"), 0o644)
		if rootHt != "" {
			os.WriteFile(filepath.Join(dir, ".htaccess"), []byte(rootHt), 0o644)
		}
		if subHt != "" {
			os.WriteFile(filepath.Join(dir, "uploads", ".htaccess"), []byte(subHt), 0o644)
		}
		return dir
	}
	dom := func(host, root string) config.Domain {
		return config.Domain{Host: host, Type: "static", Root: root, DirectoryListing: true,
			SSL: config.SSLConfig{Mode: "off"}, Htaccess: config.HtaccessConfig{Mode: "import"}}
	}
	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{
			dom("sub.test", mk("", "Options -Indexes\n")),  // per-directory -Indexes
			dom("root.test", mk("Options -Indexes\n", "")), // control: root-level -Indexes
			dom("listed.test", mk("", "")),                 // control: listing really on
		},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	get := func(host string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, "/uploads/", nil)
		req.Host = host
		req.RemoteAddr = "198.51.100.7:1"
		req.Header.Set("User-Agent", "uwas-test")
		rr := httptest.NewRecorder()
		s.handler.ServeHTTP(rr, req)
		return rr.Code, rr.Body.String()
	}
	if c, b := get("root.test"); c == 200 {
		t.Fatalf("control invalid: root-level -Indexes still lists (%d %q)", c, b)
	}
	if c, b := get("listed.test"); c != 200 || !contains(b, "private-name.txt") {
		t.Fatalf("control invalid: listing not enabled (%d)", c)
	}
	c, b := get("sub.test")
	listed := c == 200 && contains(b, "private-name.txt")
	fmt.Printf("EXPECTED: uploads/.htaccess `Options -Indexes` suppresses the listing (not 200)\nACTUAL: status %d, names listed=%v\n", c, listed)
	if listed {
		fmt.Println("PROBLEM CONFIRMED")
		t.FailNow()
	}
	fmt.Println("PROBLEM NOT REPRODUCED")
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
