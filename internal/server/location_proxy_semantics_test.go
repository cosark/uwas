package server

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func locationProxyFixture(t *testing.T, upURL string) *Server {
	t.Helper()
	return nonCanonServer(t, "", fmt.Sprintf(`    proxy: {allow_private_upstreams: true}
    locations:
      - match: /api/
        proxy_pass: %s
`, upURL))
}

func locationGet(s *Server, method, path string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	req.Host = "a.test"
	req.Header.Set("User-Agent", "uwas-test")
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

// F7500: the upstream's redirect belongs to the browser; following it inside
// UWAS swallowed the 3xx and the redirect's Set-Cookie.
func TestLocationProxyPassesUpstreamRedirectThrough(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/old":
			w.Header().Set("Location", "/api/new")
			w.Header().Set("Set-Cookie", "sid=1; Path=/")
			w.WriteHeader(http.StatusFound)
		case "/api/new":
			fmt.Fprint(w, "NEW-PAGE")
		default:
			fmt.Fprint(w, "PLAIN")
		}
	}))
	defer up.Close()
	s := locationProxyFixture(t, up.URL)

	if rec := locationGet(s, http.MethodGet, "/api/plain", nil); rec.Code != 200 || rec.Body.String() != "PLAIN" {
		t.Fatalf("control: %d %q", rec.Code, rec.Body.String())
	}
	rec := locationGet(s, http.MethodGet, "/api/old", nil)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/api/new" {
		t.Errorf("redirect: status %d Location %q, want 302 /api/new passed through", rec.Code, rec.Header().Get("Location"))
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "sid=1") {
		t.Errorf("redirect's Set-Cookie lost: %q", rec.Header().Get("Set-Cookie"))
	}
}

// F7501: one client per policy, so upstream connections are reused instead of
// a new Transport (and a leaked idle connection) per request.
func TestLocationProxyReusesUpstreamConnections(t *testing.T) {
	var conns atomic.Int64
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	up.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			conns.Add(1)
		}
	}
	up.Start()
	defer up.Close()
	s := locationProxyFixture(t, up.URL)

	for i := 0; i < 12; i++ {
		if rec := locationGet(s, http.MethodGet, "/api/x", nil); rec.Code != 200 {
			t.Fatalf("request %d: status %d", i, rec.Code)
		}
	}
	if got := conns.Load(); got > 2 {
		t.Errorf("12 sequential requests opened %d upstream connections, want keep-alive reuse (<= 2)", got)
	}
}

// F7502: a body with a Content-Length reaches the upstream with that length,
// not as chunked.
func TestLocationProxyKeepsContentLength(t *testing.T) {
	var mu sync.Mutex
	var gotLen int64
	var gotTE []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotLen, gotTE = r.ContentLength, r.TransferEncoding
		mu.Unlock()
		io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, "ok")
	}))
	defer up.Close()
	s := locationProxyFixture(t, up.URL)

	if rec := locationGet(s, http.MethodPost, "/api/x", strings.NewReader("hello")); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotLen != 5 || len(gotTE) != 0 {
		t.Errorf("upstream saw ContentLength=%d TransferEncoding=%v, want 5 and none", gotLen, gotTE)
	}
}

// F7503: an event is delivered while the upstream stream is still open.
func TestLocationProxyFlushesEventStream(t *testing.T) {
	gate := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-gate:
		case <-r.Context().Done():
		}
	}))
	defer up.Close()
	s := locationProxyFixture(t, up.URL)
	front := httptest.NewServer(s.handler)
	defer front.Close()
	defer close(gate)

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/api/stream", nil)
	req.Host = "a.test"
	req.Header.Set("User-Agent", "uwas-test")
	got := make(chan string, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			got <- "ERR " + err.Error()
			return
		}
		defer resp.Body.Close()
		line, _ := bufio.NewReader(resp.Body).ReadString('\n')
		got <- strings.TrimSpace(line)
	}()
	select {
	case line := <-got:
		if line != "data: first" {
			t.Errorf("first line = %q, want %q", line, "data: first")
		}
	case <-time.After(3 * time.Second):
		t.Error("the first event was held in the buffer while the upstream stream stayed open")
	}
}

// F7504: the client's timeout bounds the response headers, not a transfer that
// keeps delivering data.
func TestLocationProxyClientDoesNotCapStreamingTransfer(t *testing.T) {
	const chunks = 15
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < chunks; i++ {
			fmt.Fprint(w, "x")
			w.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
		}
	}))
	defer up.Close()
	resp, err := locationProxyClient(true, time.Second).Get(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || len(b) != chunks {
		t.Errorf("read %d bytes, err %v; want %d (timeout must not cut a flowing stream)", len(b), err, chunks)
	}
}

// The response-header wait is still bounded and reported as a gateway timeout.
func TestLocationProxyHeaderTimeoutIs504(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(10 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer up.Close()
	c := locationProxyClient(true, 200*time.Millisecond)
	_, err := c.Get(up.URL)
	if err == nil || !isDeadline(err) {
		t.Errorf("silent upstream: err = %v, want a timeout recognised by isDeadline", err)
	}
}
