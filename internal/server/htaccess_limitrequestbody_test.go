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
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

// F16901: "LimitRequestBody" in .htaccess was parsed by nothing, so a tenant who
// capped request bodies had no cap and the whole body reached PHP.
func TestHtaccessLimitRequestBodyRefusesLargeBodies(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"free", "capped", "capped/lifted", "capped/tighter"} {
		write(d+"/up.php", "<?php")
	}
	write("capped/.htaccess", "LimitRequestBody 100\n")
	write("capped/lifted/.htaccess", "LimitRequestBody 0\n")
	write("capped/tighter/.htaccess", "LimitRequestBody 10\n")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan int, 16)
	go fcgi.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- len(b)
		w.Write([]byte("EXECUTED"))
	}))
	// htaccess.mode is left unset: the cap is protective and holds regardless.
	s := newDispatchTestServer(t, []config.Domain{{Host: "p.test", Type: "php", Root: root,
		SSL: config.SSLConfig{Mode: "off"}, PHP: config.PHPConfig{FPMAddress: ln.Addr().String()}}})

	post := func(path string, n int, chunked bool) (code, reached int) {
		t.Helper()
		for len(got) > 0 {
			<-got
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", path, strings.NewReader(strings.Repeat("x", n)))
		if chunked {
			req.ContentLength = -1
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Host = "p.test"
		req.Header.Set("User-Agent", "uwas-test")
		s.handleRequest(rec, req)
		select {
		case l := <-got:
			return rec.Code, l
		default:
			return rec.Code, -1
		}
	}

	for _, c := range []struct {
		name string
		path string
		n    int
		code int
		pass bool // reaches PHP intact
	}{
		{"no directive: large body passes", "/free/up.php", 5000, 200, true},
		{"under the cap passes", "/capped/up.php", 50, 200, true},
		{"exactly the cap passes", "/capped/up.php", 100, 200, true},
		{"one byte over the cap is refused", "/capped/up.php", 101, 413, false},
		{"a large body is refused", "/capped/up.php", 5000, 413, false},
		{"a subdirectory lifts the cap with 0", "/capped/lifted/up.php", 5000, 200, true},
		{"a deeper cap is tighter", "/capped/tighter/up.php", 11, 413, false},
		{"a deeper cap still lets a small body in", "/capped/tighter/up.php", 10, 200, true},
	} {
		code, reached := post(c.path, c.n, false)
		if code != c.code {
			t.Errorf("%s: status %d, want %d", c.name, code, c.code)
		}
		if c.pass && reached != c.n {
			t.Errorf("%s: PHP received %d bytes, want %d", c.name, reached, c.n)
		}
		if !c.pass && reached != -1 {
			t.Errorf("%s: a refused body still reached PHP (%d bytes)", c.name, reached)
		}
	}

	// A body of unknown length cannot be judged up front; it is cut off once it
	// passes the cap, so PHP never receives more than the cap allows.
	if code, reached := post("/capped/up.php", 5000, true); reached > 100 || (code == 200 && reached == 5000) {
		t.Errorf("chunked body past the cap: status %d, PHP received %d bytes (cap 100)", code, reached)
	}
}
