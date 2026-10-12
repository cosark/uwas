package cache

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// F18202: any Set-Cookie line keeps a response out of the shared cache, not
// just the first one.
func TestIsCacheableRefusesAnySetCookieLine(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	cases := map[string][]string{
		"none":           nil,
		"single":         {"a=1"},
		"empty first":    {"", "a=1"},
		"empty only":     {""},
		"second present": {"a=1", "b=2"},
	}
	for name, vals := range cases {
		h := http.Header{}
		if vals != nil {
			h["Set-Cookie"] = vals
		}
		want := vals == nil
		if got := IsCacheable(r, 200, h); got != want {
			t.Errorf("%s: IsCacheable = %v, want %v", name, got, want)
		}
	}
}
