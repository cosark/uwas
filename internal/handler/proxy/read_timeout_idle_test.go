package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/router"
)

func serveWithReadTimeout(t *testing.T, upstream *httptest.Server, read time.Duration) *httptest.Server {
	t.Helper()
	pool := NewUpstreamPool([]UpstreamConfig{{Address: upstream.URL, Weight: 1}})
	d := newTestDomain()
	d.Proxy.Timeouts.Read.Duration = read
	h := New(newTestLogger())
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.Serve(router.AcquireContext(w, r), d, pool, firstBackend{})
	}))
	t.Cleanup(front.Close)
	return front
}

// The read timeout measures upstream silence, not total transfer time: an
// event stream whose gaps stay inside the timeout must outlive it (F3701).
func TestReadTimeoutIsIdleTimeoutForStreamingBody(t *testing.T) {
	const chunks = 6
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		for i := 0; i < chunks; i++ {
			fmt.Fprintf(w, "data: %d\n\n", i)
			w.(http.Flusher).Flush()
			time.Sleep(150 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	front := serveWithReadTimeout(t, upstream, 400*time.Millisecond) // 900ms stream > 400ms timeout
	resp, err := http.Get(front.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if got := strings.Count(string(b), "data: "); got != chunks {
		t.Fatalf("stream delivered %d events, want %d", got, chunks)
	}
}

// A stalled body is still cut once the upstream stays silent past the read
// timeout, and a stall before the headers is still a 504.
func TestReadTimeoutStillBoundsSilence(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	stallBody := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("first"))
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer stallBody.Close()
	front := serveWithReadTimeout(t, stallBody, 200*time.Millisecond)
	resp, err := http.Get(front.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body) // returns once the proxy gives up; release has not fired
	resp.Body.Close()
	if string(b) != "first" {
		t.Fatalf("stalled body = %q, want %q then end", b, "first")
	}

	stallHeader := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer stallHeader.Close()
	front2 := serveWithReadTimeout(t, stallHeader, 200*time.Millisecond)
	resp2, err := http.Get(front2.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("header stall status = %d, want 504", resp2.StatusCode)
	}
}
