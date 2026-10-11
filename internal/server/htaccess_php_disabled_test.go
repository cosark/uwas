package server

import (
	"net"
	"net/http"
	"net/http/fcgi"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

// F12100: "php_flag engine off", "RemoveHandler .php" and "SetHandler none" in
// uploads/.htaccess are the usual way to keep uploaded scripts from running.
// They were parsed and ignored, so the script was handed to PHP-FPM.
func TestHtaccessDisablingPHPStopsExecution(t *testing.T) {
	root := t.TempDir()
	cases := map[string]string{
		"control": "# nothing\n",
		"engine":  "php_flag engine off\n",
		"remove":  "RemoveHandler .php\n",
		"sethand": "SetHandler none\n",
		"modphp":  "<IfModule mod_php7.c>\nphp_flag engine off\n</IfModule>\n",
		"deny":    "<FilesMatch \"\\.php$\">\nRequire all denied\n</FilesMatch>\n",
	}
	for name, ht := range cases {
		d := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Join(d, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{"shell.php", "sub/inner.php"} {
			if err := os.WriteFile(filepath.Join(d, f), []byte("<?php echo 1;"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(d, ".htaccess"), []byte(ht), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A subdirectory that switches the engine back on keeps working.
	os.MkdirAll(filepath.Join(root, "engine", "ok"), 0o755)
	os.WriteFile(filepath.Join(root, "engine", "ok", "run.php"), []byte("<?php"), 0o644)
	os.WriteFile(filepath.Join(root, "engine", "ok", ".htaccess"), []byte("php_flag engine on\n"), 0o644)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ran := make(chan string, 32)
	go fcgi.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran <- fcgi.ProcessEnv(r)["SCRIPT_FILENAME"]
		w.Write([]byte("EXECUTED"))
	}))
	s := newDispatchTestServer(t, []config.Domain{{Host: "p.test", Type: "php", Root: root,
		SSL: config.SSLConfig{Mode: "off"}, PHP: config.PHPConfig{FPMAddress: ln.Addr().String()}}})

	get := func(path string) (int, bool) {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		req.Host = "p.test"
		req.Header.Set("User-Agent", "uwas-test")
		s.handleRequest(rec, req)
		select {
		case <-ran:
			return rec.Code, true
		default:
			return rec.Code, false
		}
	}
	for _, c := range []struct {
		path string
		run  bool
	}{
		{"/control/shell.php", true},
		{"/control/sub/inner.php", true},
		{"/engine/shell.php", false},
		{"/engine/sub/inner.php", false}, // inherited by the subdirectory
		{"/engine/ok/run.php", true},     // engine on lifts it
		{"/remove/shell.php", false},
		{"/sethand/shell.php", false},
		{"/modphp/shell.php", false},
		{"/deny/shell.php", false},
	} {
		code, executed := get(c.path)
		if executed != c.run {
			t.Errorf("%s: executed=%v (status %d), want executed=%v", c.path, executed, code, c.run)
		}
		if !c.run && code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", c.path, code)
		}
	}
}
