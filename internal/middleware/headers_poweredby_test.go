package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// F8820: X-Powered-By set by a backend or PHP-FPM while the response is
// written must not reach the client.
func TestSecurityHeadersStripsPoweredByAtCommit(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"write": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Powered-By", "PHP/8.3.1")
			w.Write([]byte("x"))
		},
		"writeheader": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Powered-By", "PHP/8.3.1")
			w.WriteHeader(http.StatusCreated)
		},
		"flush": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Powered-By", "PHP/8.3.1")
			w.(http.Flusher).Flush()
		},
		"after informational": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusEarlyHints)
			w.Header().Set("X-Powered-By", "PHP/8.3.1")
			w.Write([]byte("x"))
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(SecurityHeaders()(h))
			defer srv.Close()
			resp, err := http.Get(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if v := resp.Header.Get("X-Powered-By"); v != "" {
				t.Errorf("X-Powered-By = %q, want absent", v)
			}
			if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
				t.Error("default security headers missing")
			}
		})
	}
}

// Through the compression middleware, as the server chains them, the buffered
// and the compressed path both commit through the stripper.
func TestSecurityHeadersStripsPoweredByThroughCompress(t *testing.T) {
	body := strings.Repeat("hello ", 600)
	h := Chain(SecurityHeaders(), CompressWith(1024, nil))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Powered-By", "PHP/8.3.1")
		w.Write([]byte(body))
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := (&http.Client{Transport: &http.Transport{DisableCompression: true}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip (test premise)", resp.Header.Get("Content-Encoding"))
	}
	if v := resp.Header.Get("X-Powered-By"); v != "" {
		t.Errorf("X-Powered-By = %q, want absent", v)
	}
}

// The wrapper must keep Flush and Hijack reachable for streaming and WebSocket handlers.
func TestSecurityHeadersWriterKeepsFlushAndHijack(t *testing.T) {
	var flusher, hijacker bool
	srv := httptest.NewServer(SecurityHeaders()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, flusher = w.(http.Flusher)
		_, hijacker = w.(http.Hijacker)
		w.WriteHeader(http.StatusNoContent)
	})))
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
