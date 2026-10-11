package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func locHeaderReq(s *Server, p string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, p, nil)
	req.Host = "a.test"
	req.RemoteAddr = "192.0.2.5:1"
	req.Header.Set("User-Agent", "uwas-test")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("X-Strip", "c")
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

// F4200: the location proxy response copy replaced the Vary the compression
// middleware had set, so a shared cache could serve a gzip body to a client
// that did not ask for it.
func TestLocationProxyMergesVary(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Vary", "Cookie")
		fmt.Fprint(w, strings.Repeat("x", 4096))
	}))
	defer up.Close()
	s := nonCanonServer(t, "", fmt.Sprintf(`    proxy: {allow_private_upstreams: true}
    locations:
      - match: /api/
        proxy_pass: %s
`, up.URL))
	rec := locHeaderReq(s, "/api/x")
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	got := strings.Join(rec.Header().Values("Vary"), ", ")
	if !strings.Contains(got, "Accept-Encoding") || !strings.Contains(got, "Cookie") {
		t.Errorf("Vary = %q, want Accept-Encoding and Cookie", got)
	}
}

// F4201: domain headers.request_add/request_remove/response_add/response_remove
// ran after the locations loop, so a location's proxy_pass/redirect/root answer
// skipped all four.
func TestLocationAppliesDomainHeaderTransforms(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "secret-stack")
		fmt.Fprintf(w, "inject=%s cookie=%s", r.Header.Get("X-Inject"), r.Header.Get("X-Strip"))
	}))
	defer up.Close()
	s := nonCanonServer(t, "", fmt.Sprintf(`    proxy: {allow_private_upstreams: true}
    headers:
      response_add: {X-Policy: "on"}
      response_remove: [X-Powered-By]
      request_add: {X-Inject: "v"}
      request_remove: [X-Strip]
    locations:
      - match: /api/
        proxy_pass: %s
      - match: /old
        redirect: /new
`, up.URL))
	if rec := locHeaderReq(s, "/index.html"); rec.Header().Get("X-Policy") != "on" {
		t.Fatalf("control: main path X-Policy = %q", rec.Header().Get("X-Policy"))
	}
	rec := locHeaderReq(s, "/api/x")
	if rec.Header().Get("X-Policy") != "on" || rec.Header().Get("X-Powered-By") != "" {
		t.Errorf("proxy response headers: X-Policy=%q X-Powered-By=%q", rec.Header().Get("X-Policy"), rec.Header().Get("X-Powered-By"))
	}
	if rec.Body.String() != "inject=v cookie=" {
		t.Errorf("upstream saw %q, want inject=v cookie=", rec.Body.String())
	}
	if rec := locHeaderReq(s, "/old"); rec.Header().Get("X-Policy") != "on" {
		t.Errorf("redirect X-Policy = %q", rec.Header().Get("X-Policy"))
	}
}
