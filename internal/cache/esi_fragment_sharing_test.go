package cache

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type sharingFetcher struct {
	calls int
	hdr   http.Header
}

func (f *sharingFetcher) FetchFragment(host, path string, _ *http.Request) ([]byte, int, http.Header, error) {
	f.calls++
	return []byte(fmt.Sprintf("frag#%d", f.calls)), 200, f.hdr.Clone(), nil
}

// F3401: an ESI fragment the origin marked no-store/private, or that sets a
// cookie or varies on a cookie, must not be served from the shared cache to
// the next visitor.
func TestESIFragmentSharingHonoursOriginHeaders(t *testing.T) {
	fetches := func(hdr http.Header) int {
		eng := NewEngine(context.Background(), 1<<20, "", 0, nil)
		f := &sharingFetcher{hdr: hdr}
		p := NewESIProcessor(eng, f, nil, 3)
		body := []byte(`<!--esi <esi:include src="/frag"/> -->`)
		req := httptest.NewRequest("GET", "http://h/", nil)
		p.Process(body, "h", req, nil, 0)
		p.Process(body, "h", req, nil, 0)
		return f.calls
	}
	h := func(k, v string) http.Header { return http.Header{k: {v}} }

	for name, tc := range map[string]struct {
		hdr  http.Header
		want int
	}{
		"control public max-age":  {h("Cache-Control", "public, max-age=60"), 1},
		"no header (default ttl)": {http.Header{}, 1},
		"no-store":                {h("Cache-Control", "no-store"), 2},
		"private":                 {h("Cache-Control", "Private, max-age=60"), 2},
		"set-cookie":              {h("Set-Cookie", "csrf=abc"), 2},
		"vary cookie":             {h("Vary", "Cookie"), 2},
	} {
		if got := fetches(tc.hdr); got != tc.want {
			t.Errorf("%s: fragment fetched %d times, want %d", name, got, tc.want)
		}
	}
}
