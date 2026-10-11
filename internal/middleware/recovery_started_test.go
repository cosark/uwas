package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/logger"
)

func recoveryGet(t *testing.T, h http.Handler, acceptEncoding string) (int, string, error) {
	t.Helper()
	log := logger.New("error", "text")
	srv := httptest.NewServer(Chain(Recovery(log), CompressWith(1024, nil))(h))
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Accept-Encoding", acceptEncoding)
	resp, err := (&http.Client{Transport: &http.Transport{DisableCompression: true}}).Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), err
}

// F8800: a panic after the response has started must abort the transfer
// instead of appending an error page to the partial body.
func TestRecoveryAbortsResponseAlreadyStarted(t *testing.T) {
	partial := strings.Repeat("A", 4000)
	for _, enc := range []string{"identity", "gzip"} {
		t.Run(enc, func(t *testing.T) {
			_, body, err := recoveryGet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.Write([]byte(partial))
				w.(http.Flusher).Flush()
				panic("boom after start")
			}), enc)
			if err == nil {
				t.Errorf("transfer ended cleanly (%d bytes); want an aborted transfer", len(body))
			}
			if strings.Contains(body, "500 Internal Server Error") {
				t.Error("error text appended to a response that had already started")
			}
		})
	}
}

// Before anything is written the panic is still answered with a clean 500.
func TestRecoveryBeforeWriteStillReturns500(t *testing.T) {
	st, body, err := recoveryGet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}), "identity")
	if err != nil || st != http.StatusInternalServerError || !strings.Contains(body, "500 Internal Server Error") {
		t.Fatalf("status=%d err=%v body=%q", st, err, body)
	}
	// An informational response is not a started response.
	st, body, err = recoveryGet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusEarlyHints)
		panic("boom after 103")
	}), "identity")
	if err != nil || st != http.StatusInternalServerError {
		t.Fatalf("after 103: status=%d err=%v body=%q", st, err, body)
	}
}

// The wrapper must keep Flush and Hijack reachable for streaming and WebSocket
// handlers.
func TestRecoveryWriterKeepsFlushAndHijack(t *testing.T) {
	log := logger.New("error", "text")
	var flusher, hijacker bool
	h := Recovery(log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, flusher = w.(http.Flusher)
		_, hijacker = w.(http.Hijacker)
		w.WriteHeader(http.StatusNoContent)
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !flusher || !hijacker {
		t.Errorf("Flusher=%v Hijacker=%v, want both", flusher, hijacker)
	}
}
