package server

import (
	"bufio"
	"fmt"
	"io"
	"net"
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

// F15600: static files, directory listings and location roots answered every
// HTTP method with 200 and the whole file. nginx and Apache answer anything
// but GET, HEAD and POST with 405, and OPTIONS with the allowed set.
func TestStaticContentRefusesUnsupportedMethods(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "data.txt"), []byte("STATIC-BODY"), 0o644)
	os.MkdirAll(filepath.Join(dir, "lst"), 0o755)
	os.WriteFile(filepath.Join(dir, "lst", "a.txt"), []byte("x"), 0o644)
	os.MkdirAll(filepath.Join(dir, "loc"), 0o755)
	os.WriteFile(filepath.Join(dir, "loc", "f.txt"), []byte("LOC-BODY"), 0o644)

	cfg := &config.Config{Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text",
		Cache: config.CacheConfig{Enabled: true, MemoryLimit: config.ByteSize(4 << 20), DefaultTTL: 60}},
		Domains: []config.Domain{{Host: "d.test", Type: "static", Root: dir, DirectoryListing: true,
			SSL:       config.SSLConfig{Mode: "off"},
			Cache:     config.DomainCache{Enabled: true, TTL: 60},
			Locations: []config.LocationConfig{{Match: "/loc/", Root: filepath.Join(dir, "loc")}}}}}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	srv := httptest.NewServer(http.HandlerFunc(s.handleHTTP))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	do := func(method, path string) (int, string, string) {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(c, "%s %s HTTP/1.1\r\nHost: d.test\r\nUser-Agent: t\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", method, path)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Get("Allow"), string(body)
	}

	t.Run("safe methods keep working", func(t *testing.T) {
		for _, c := range []struct{ m, p, want string }{
			{"GET", "/data.txt", "STATIC-BODY"},
			{"POST", "/data.txt", "STATIC-BODY"},
			{"GET", "/loc/f.txt", "LOC-BODY"},
		} {
			if st, _, body := do(c.m, c.p); st != 200 || body != c.want {
				t.Errorf("%s %s = %d %q, want 200 %q", c.m, c.p, st, body, c.want)
			}
		}
		if st, _, body := do("HEAD", "/data.txt"); st != 200 || body != "" {
			t.Errorf("HEAD = %d %q, want 200 with no body", st, body)
		}
		if st, _, body := do("GET", "/lst/"); st != 200 || !strings.Contains(body, "a.txt") {
			t.Errorf("GET listing = %d %q", st, body)
		}
	})

	t.Run("other methods are refused", func(t *testing.T) {
		for _, p := range []string{"/data.txt", "/lst/", "/loc/f.txt"} {
			for _, m := range []string{"PUT", "DELETE", "PATCH", "PROPFIND", "TRACE", "FOO"} {
				st, allow, body := do(m, p)
				if st != http.StatusMethodNotAllowed || allow != "GET, HEAD, POST, OPTIONS" {
					t.Errorf("%s %s = %d Allow=%q, want 405 with the allowed set", m, p, st, allow)
				}
				if strings.Contains(body, "STATIC-BODY") || strings.Contains(body, "LOC-BODY") {
					t.Errorf("%s %s leaked the file: %q", m, p, body)
				}
			}
		}
	})

	t.Run("OPTIONS names the allowed set and sends no body", func(t *testing.T) {
		for _, p := range []string{"/data.txt", "/lst/", "/loc/f.txt"} {
			if st, allow, body := do("OPTIONS", p); st != 200 || allow != "GET, HEAD, POST, OPTIONS" || body != "" {
				t.Errorf("OPTIONS %s = %d Allow=%q body=%q", p, st, allow, body)
			}
		}
	})

	t.Run("a cached GET is not replayed to another method", func(t *testing.T) {
		do("GET", "/data.txt")
		do("GET", "/data.txt")
		if st, _, body := do("DELETE", "/data.txt"); st != http.StatusMethodNotAllowed || strings.Contains(body, "STATIC-BODY") {
			t.Errorf("DELETE after a cached GET = %d %q, want 405", st, body)
		}
	})
}
