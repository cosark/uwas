package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F14705: a body whose Content-Length is already over maxCacheableBody is never
// stored, so responseCapture must not copy it. It used to copy up to the limit
// on every request, growing a buffer of that size only to drop it.
func TestResponseCaptureSkipsBodiesDeclaredOverTheLimit(t *testing.T) {
	capture := func(contentLength string, writes int, chunk int) *responseCapture {
		rc := newResponseCapture(httptest.NewRecorder())
		if contentLength != "" {
			rc.Header().Set("Content-Length", contentLength)
		}
		rc.WriteHeader(http.StatusOK)
		for i := 0; i < writes; i++ {
			rc.Write(make([]byte, chunk))
		}
		return rc
	}

	t.Run("declared over the limit is not buffered", func(t *testing.T) {
		rc := capture(strconv.Itoa(maxCacheableBody+1), 8, 32<<10)
		if !rc.overflow || rc.body.Len() != 0 {
			t.Errorf("overflow=%v, %d bytes buffered; want overflow and nothing copied", rc.overflow, rc.body.Len())
		}
	})
	t.Run("declared within the limit is captured (control)", func(t *testing.T) {
		rc := capture(strconv.Itoa(8*(32<<10)), 8, 32<<10)
		if rc.overflow || rc.body.Len() != 8*(32<<10) {
			t.Errorf("overflow=%v, %d bytes buffered; want the whole body", rc.overflow, rc.body.Len())
		}
	})
	t.Run("declared exactly at the limit is still captured", func(t *testing.T) {
		rc := capture(strconv.Itoa(maxCacheableBody), 1, 1<<10)
		if rc.overflow {
			t.Error("a body of exactly maxCacheableBody was refused")
		}
	})
	t.Run("an unreadable length changes nothing", func(t *testing.T) {
		rc := capture("not-a-number", 2, 1<<10)
		if rc.overflow || rc.body.Len() != 2<<10 {
			t.Errorf("overflow=%v, %d bytes buffered", rc.overflow, rc.body.Len())
		}
	})
	t.Run("no length: buffered up to the limit, then dropped", func(t *testing.T) {
		rc := capture("", 1, maxCacheableBody)
		if rc.overflow || rc.body.Len() != maxCacheableBody {
			t.Fatalf("at the limit: overflow=%v len=%d", rc.overflow, rc.body.Len())
		}
		rc.Write([]byte("x"))
		if !rc.overflow || rc.body.Len() != 0 {
			t.Errorf("past the limit: overflow=%v len=%d, want overflow and an empty buffer", rc.overflow, rc.body.Len())
		}
	})
}

// The same through the server: a large static file is not cached, a small one is.
func TestLargeKnownLengthResponseIsNotCached(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "big.css"))
	if err != nil {
		t.Fatal(err)
	}
	f.Truncate(maxCacheableBody + 1<<20)
	f.Close()
	os.WriteFile(filepath.Join(dir, "small.css"), make([]byte, 4096), 0o644)

	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text",
			Cache: config.CacheConfig{Enabled: true, MemoryLimit: config.ByteSize(64 << 20), DiskPath: t.TempDir(), DiskLimit: config.ByteSize(64 << 20)}},
		Domains: []config.Domain{{Host: "c.test", Type: "static", Root: dir, SSL: config.SSLConfig{Mode: "off"},
			Cache: config.DomainCache{Enabled: true, TTL: 60}}},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	get := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Host = "c.test"
		r.RemoteAddr = "192.0.2.5:1"
		r.Header.Set("User-Agent", "uwas-test")
		w := httptest.NewRecorder()
		s.handler.ServeHTTP(w, r)
		return w
	}

	get("/small.css")
	if got := get("/small.css").Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("control: small file X-Cache = %q, want HIT", got)
	}
	get("/big.css")
	rec := get("/big.css")
	if rec.Code != http.StatusOK || rec.Body.Len() != maxCacheableBody+1<<20 {
		t.Fatalf("the large file was not served whole: status %d, %d bytes", rec.Code, rec.Body.Len())
	}
	if got := rec.Header().Get("X-Cache"); got == "HIT" {
		t.Error("a file over the cache limit was served from the cache")
	}
}
