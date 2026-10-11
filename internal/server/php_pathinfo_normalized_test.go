package server

import (
	"net"
	"net/http"
	"net/http/fcgi"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

// F8400: PATH_TRANSLATED/PATH_INFO were built from the raw request path, so a
// crafted "/blog/../../../etc/passwd" reached PHP with PATH_TRANSLATED pointing
// outside the document root (Apache and nginx normalize before CGI).
func TestPHPPathInfoDotSegmentsStayInsideRoot(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php"), 0o644)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	got := make(chan map[string]string, 4)
	go fcgi.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- fcgi.ProcessEnv(r)
		w.Write([]byte("ok"))
	}))
	s := newDispatchTestServer(t, []config.Domain{{Host: "p.test", Type: "php", Root: root, SSL: config.SSLConfig{Mode: "off"},
		PHP: config.PHPConfig{FPMAddress: ln.Addr().String(), IndexFiles: []string{"index.php"}}}})
	pt := func(p string) string {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", p, nil)
		req.Host = "p.test"
		req.Header.Set("User-Agent", "t")
		s.handleRequest(rec, req)
		select {
		case env := <-got:
			return env["PATH_TRANSLATED"]
		default:
			return "<no fpm call>"
		}
	}
	// Control: an ordinary front-controller URL keeps PATH_TRANSLATED under the root.
	ctl := pt("/blog/post")
	if ctl != root+"/blog/post" {
		t.Fatalf("control request PATH_TRANSLATED=%q", ctl)
	}
	for _, p := range []string{"/blog/../../../etc/passwd", "/blog/%2e%2e/%2e%2e/etc/passwd"} {
		got := pt(p)
		if !strings.HasPrefix(filepath.Clean(got), root+string(filepath.Separator)) {
			t.Errorf("%s: PATH_TRANSLATED=%q leaves the document root", p, got)
		}
	}
}
