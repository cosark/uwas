package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A streamed upload whose pauses stay inside the read timeout must outlive it:
// the timeout measures client silence, not total transfer time (F4000).
func TestReadTimeoutIsIdleTimeoutForStreamedUpload(t *testing.T) {
	var got int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	front := serveWithReadTimeout(t, upstream, 300*time.Millisecond)

	pr, pw := io.Pipe() // unknown length: streamed, not buffered
	go func() {
		for i := 0; i < 8; i++ { // 800ms in total, 100ms gaps
			_, _ = pw.Write([]byte("0123456789"))
			time.Sleep(100 * time.Millisecond)
		}
		_ = pw.Close()
	}()
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/upload", pr)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || got != 80 {
		t.Fatalf("status=%d bytes=%d, want 200 and 80", resp.StatusCode, got)
	}
}

// Once a streamed upload is fully sent, an upstream that then stays silent past
// the read timeout is still a 504.
func TestReadTimeoutStillBoundsSilenceAfterStreamedUpload(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer upstream.Close()
	front := serveWithReadTimeout(t, upstream, 200*time.Millisecond)

	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte("start"))
		_ = pw.Close()
	}()
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/upload", pr)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", resp.StatusCode)
	}
}

// A body past the retry buffer is streamed with the client's Content-Length,
// not re-framed as chunked (F4001); bodies at or under the buffer keep theirs.
func TestStreamedBodyKeepsContentLength(t *testing.T) {
	var cl int64
	var te []string
	var n int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, te = r.ContentLength, r.TransferEncoding
		n, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	front := serveWithReadTimeout(t, upstream, 30*time.Second)

	for _, size := range []int64{0, 1, maxRetryBodyBytes, maxRetryBodyBytes + 1} {
		cl, te, n = -2, nil, 0
		resp, err := http.Post(front.URL+"/up", "application/octet-stream", bytes.NewReader(make([]byte, size)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if cl != size || len(te) != 0 || n != size {
			t.Fatalf("size %d: upstream ContentLength=%d TransferEncoding=%v received=%d", size, cl, te, n)
		}
	}
}
