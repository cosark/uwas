package proxy

import (
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/middleware"
	"github.com/uwaserver/uwas/internal/router"
)

// An upstream Vary must be merged with the Vary UWAS already set, not replace
// it: the compressed response still depends on Accept-Encoding (F4002).
func TestUpstreamVaryMergedWithCompressionVary(t *testing.T) {
	body := strings.Repeat("hello world ", 200)
	cases := []struct {
		name, upstream string
		want           []string
	}{
		{"none", "", []string{"Accept-Encoding"}},
		{"cookie", "Cookie", []string{"Accept-Encoding", "Cookie"}},
		{"duplicate case-insensitive", "accept-encoding, Cookie", []string{"Accept-Encoding", "Cookie"}},
		{"star", "*", []string{"Accept-Encoding", "*"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				if tc.upstream != "" {
					w.Header().Set("Vary", tc.upstream)
				}
				_, _ = w.Write([]byte(body))
			}))
			defer up.Close()
			pool := NewUpstreamPool([]UpstreamConfig{{Address: up.URL, Weight: 1}})
			h := New(newTestLogger())
			front := httptest.NewServer(middleware.Compress(100)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				h.Serve(router.AcquireContext(w, r), newTestDomain(), pool, firstBackend{})
			})))
			defer front.Close()

			req, _ := http.NewRequest(http.MethodGet, front.URL+"/", nil)
			req.Header.Set("Accept-Encoding", "gzip")
			resp, err := (&http.Transport{DisableCompression: true}).RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.Header.Get("Content-Encoding") != "gzip" {
				t.Fatalf("Content-Encoding = %q, want gzip", resp.Header.Get("Content-Encoding"))
			}
			if _, err := gzip.NewReader(resp.Body); err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, v := range resp.Header.Values("Vary") {
				for _, n := range strings.Split(v, ",") {
					got = append(got, strings.TrimSpace(n))
				}
			}
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("Vary = %v, want %v", got, tc.want)
			}
		})
	}
}
