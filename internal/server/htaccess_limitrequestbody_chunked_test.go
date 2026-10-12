package server

import (
	"io"
	"net"
	"net/http"
	"net/http/fcgi"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

// F17401: a chunked body past "LimitRequestBody" must not run the script to
// completion with a truncated body. The fake FastCGI backend records whether
// the handler finished reading its stdin and answered; for an over-cap body
// the client must see an error status and the script must not complete.
func TestHtaccessLimitRequestBodyChunkedNeverCompletes(t *testing.T) {
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "c"), 0o755))
	must(os.WriteFile(filepath.Join(root, "c/up.php"), []byte("<?php"), 0o644))
	must(os.WriteFile(filepath.Join(root, "c/.htaccess"), []byte("LimitRequestBody 100\n"), 0o644))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	t.Cleanup(func() { ln.Close() })
	var completed atomic.Int32
	go fcgi.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err == nil {
			completed.Add(1)
		}
		w.Write([]byte("EXECUTED"))
	}))
	s := newDispatchTestServer(t, []config.Domain{{Host: "p.test", Type: "php", Root: root,
		SSL: config.SSLConfig{Mode: "off"}, PHP: config.PHPConfig{FPMAddress: ln.Addr().String()}}})

	for _, n := range []int{101, 5000, 1 << 20} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/c/up.php", strings.NewReader(strings.Repeat("x", n)))
		req.ContentLength = -1 // chunked: length unknown up front
		req.Host = "p.test"
		req.Header.Set("User-Agent", "uwas-test")
		s.handleRequest(rec, req)
		if rec.Code < 400 || strings.Contains(rec.Body.String(), "EXECUTED") {
			t.Errorf("%d-byte chunked body: status %d body %q, want an error and no execution", n, rec.Code, rec.Body.String())
		}
	}
	if completed.Load() != 0 {
		t.Errorf("script completed %d time(s) on a truncated body", completed.Load())
	}
	// Control: a chunked body inside the cap runs normally.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/c/up.php", strings.NewReader(strings.Repeat("x", 100)))
	req.ContentLength = -1
	req.Host = "p.test"
	req.Header.Set("User-Agent", "uwas-test")
	s.handleRequest(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "EXECUTED") || completed.Load() != 1 {
		t.Errorf("control: status %d body %q completed %d", rec.Code, rec.Body.String(), completed.Load())
	}
}
