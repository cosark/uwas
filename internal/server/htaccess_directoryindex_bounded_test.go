package server

import (
	"fmt"
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

// F14402: .htaccess DirectoryIndex lines accumulate, and the static handler
// stats every name for each directory request. 200 lines of ~700 names made a
// 113k-name list: 3.9 s for one GET /. Only the first config.MaxIndexFiles names
// are tried.
func TestHtaccessDirectoryIndexNamesAreBounded(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "idx.html"), []byte("INDEX"), 0o644)
	os.WriteFile(filepath.Join(dir, "last.html"), []byte("LAST"), 0o644)

	var near strings.Builder
	near.WriteString("DirectoryIndex nothere.html idx.html\n")
	os.WriteFile(filepath.Join(dir, ".htaccess"), []byte(near.String()), 0o644)

	cfg := &config.Config{Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{{Host: "d.test", Type: "static", Root: dir, Htaccess: config.HtaccessConfig{Mode: "import"}, SSL: config.SSLConfig{Mode: "off"}}}}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	get := func(path string) (int, string, time.Duration) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "d.test"
		req.RemoteAddr = "198.51.100.1:1"
		req.Header.Set("User-Agent", "uwas-test")
		rec := httptest.NewRecorder()
		st := time.Now()
		s.handler.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String(), time.Since(st)
	}
	if c, b, _ := get("/"); c != http.StatusOK || b != "INDEX" {
		t.Fatalf("control: DirectoryIndex with a missing name first = %d %q, want 200 INDEX", c, b)
	}

	// 199 lines of 300 names (a line may be 4096 bytes), the only existing
	// one past the limit.
	var many strings.Builder
	n := 0
	for line := 0; line < 199; line++ {
		many.WriteString("DirectoryIndex")
		for i := 0; i < 300; i++ {
			fmt.Fprintf(&many, " n%d.html", n)
			n++
		}
		many.WriteString("\n")
	}
	many.WriteString("DirectoryIndex last.html\n")
	os.Remove(filepath.Join(dir, "idx.html")) // nothing earlier in the list may serve
	os.WriteFile(filepath.Join(dir, ".htaccess"), []byte(many.String()), 0o644)
	c, b, took := get("/")
	if c == http.StatusInternalServerError {
		t.Fatalf("GET / = 500: the .htaccess did not parse, so this exercises nothing")
	}
	if c == http.StatusOK && b == "LAST" {
		t.Errorf("a DirectoryIndex name %d places down the list was honoured", n)
	}
	if took > 2*time.Second {
		t.Errorf("GET / with %d DirectoryIndex names took %v", n, took)
	}
}
