package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"sync"
	"testing"
)

// F18200: a location's proxy_pass may carry a base path ("http://up/public").
// The remainder of the client's path was appended verbatim, so dot segments
// that survive the location match (it matches the canonical path) were left in
// the upstream request line: "/api/x/../../../private" became
// "/public/api/x/../../../private", which any normalising origin resolves to
// "/private", outside the subtree the operator exposed.
func TestLocationProxyPassStaysUnderBasePath(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.RequestURI)
		mu.Unlock()
		fmt.Fprint(w, "ok")
	}))
	defer up.Close()

	for _, strip := range []bool{false, true} {
		strip := strip
		t.Run(fmt.Sprintf("strip_prefix=%v", strip), func(t *testing.T) {
			s := nonCanonServer(t, "", fmt.Sprintf(`    proxy: {allow_private_upstreams: true}
    locations:
      - match: /api/
        proxy_pass: %s/public
        strip_prefix: %v
`, up.URL, strip))
			// Control: a plain path stays under /public.
			// Attacks: dot segments (plain, encoded) that still match /api/ once cleaned.
			cases := []struct {
				name, req string
				control   bool
			}{
				{"control", "/api/x", true},
				{"dotdot", "/api/x/../../../private", false},
				{"dotdot-api", "/api/x/../../../api/y", false},
				{"dotdot-api2", "/api/x/../../api/y", false},
				{"encoded", "/api/x/%2e%2e/%2e%2e/%2e%2e/api/y", false},
				{"mixed", "/api/./x/..%2f..%2f..%2fapi/y", false},
			}
			for _, c := range cases {
				mu.Lock()
				seen = nil
				mu.Unlock()
				rec := locationGet(s, http.MethodGet, c.req, nil)
				mu.Lock()
				got := append([]string(nil), seen...)
				mu.Unlock()
				if len(got) == 0 {
					if c.control {
						t.Fatalf("control %s: not forwarded (status %d)", c.req, rec.Code)
					}
					continue // refused before reaching the origin: fine
				}
				u, err := url.ParseRequestURI(got[0])
				if err != nil {
					t.Errorf("%s: upstream request line %q unparsable: %v", c.name, got[0], err)
					continue
				}
				resolved := path.Clean(u.Path)
				if resolved != "/public" && !strings.HasPrefix(resolved, "/public/") {
					t.Errorf("EXPECTED: %s stays under /public\nACTUAL: upstream got %q, which resolves to %q", c.name, got[0], resolved)
				}
			}
		})
	}
}

func TestCleanProxyPassPath(t *testing.T) {
	ok := map[string]string{
		"/":                "/",
		"/a/b":             "/a/b",
		"/a/b/":            "/a/b/",
		"/a/./b":           "/a/b",
		"/a/../b":          "/b",
		"/../x":            "/x",
		"/a/b/..":          "/a/",
		"/a/b/.":           "/a/b/",
		"/a%2Fb/c":         "/a%2Fb/c",
		"/a/%2e%2E/b":      "/b",
		"//a":              "//a",
		"/a/x%20y?":        "/a/x%20y?",
		"/a/..":            "/",
		"/a/../../../b/c/": "/b/c/",
	}
	for in, want := range ok {
		if got, good := cleanProxyPassPath(in); !good || got != want {
			t.Errorf("cleanProxyPassPath(%q) = %q, %v; want %q", in, got, good, want)
		}
	}
	for _, in := range []string{"/a/..%2f..%2fb", "/a/%2e%2e%2fb", "/a/%zz"} {
		if got, good := cleanProxyPassPath(in); good {
			t.Errorf("cleanProxyPassPath(%q) = %q, want refusal", in, got)
		}
	}
	if got, good := cleanProxyPassPath("*"); !good || got != "*" {
		t.Errorf("non-rooted path changed: %q %v", got, good)
	}
}
