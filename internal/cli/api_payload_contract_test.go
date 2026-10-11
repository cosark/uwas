package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

// The admin API decodes domain and settings bodies strictly (F13701, F13700):
// a key the model does not have is a 400. The bodies the CLI sends must still
// decode, so a renamed config field cannot silently turn "uwas domain add"
// into a 400.
func TestCLIRequestBodiesDecodeStrictly(t *testing.T) {
	bodies := map[string][]byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies[r.Method+" "+r.URL.Path] = b
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{}`)
	}))
	defer srv.Close()

	run := func(cmd Command, args ...string) {
		t.Helper()
		var err error
		captureStdout(t, func() { err = cmd.Run(args) })
		if err != nil {
			t.Fatalf("%s %v: %v", cmd.Name(), args, err)
		}
	}
	run(&DomainCommand{}, "add", "--api-url", srv.URL, "--type", "php", "--root", "/var/www/shop/public_html", "--ssl", "auto", "shop.example")
	run(&CacheCommand{}, "purge", "--api-url", srv.URL, "--tag", "site:shop.example")
	run(&PHPCommand{}, "start", "--api-url", srv.URL, "--port", "9001", "8.3")

	strict := func(key string, into any) {
		t.Helper()
		body, ok := bodies[key]
		if !ok {
			t.Fatalf("no request recorded for %s", key)
		}
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(into); err != nil {
			t.Errorf("%s body %s does not decode strictly: %v", key, body, err)
		}
	}

	var d config.Domain
	strict("POST /api/v1/domains", &d)
	if d.Host != "shop.example" || d.Type != "php" || d.Root != "/var/www/shop/public_html" || d.SSL.Mode != "auto" {
		t.Errorf("domain add body decoded to %+v", d)
	}
	var purge struct {
		Tag  string `json:"tag"`
		Host string `json:"host"`
	}
	strict("POST /api/v1/cache/purge", &purge)
	if purge.Tag != "site:shop.example" {
		t.Errorf("purge tag = %q", purge.Tag)
	}
	var start struct {
		ListenAddr string `json:"listen_addr"`
	}
	strict("POST /api/v1/php/8.3/start", &start)
	if !strings.HasSuffix(start.ListenAddr, ":9001") {
		t.Errorf("php start listen_addr = %q", start.ListenAddr)
	}
}
