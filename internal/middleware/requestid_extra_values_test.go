package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// F10301: only the first X-Request-ID value was validated; further values were
// forwarded upstream unbounded and contradicted the ID stamped on the response.
func TestRequestIDDropsExtraValues(t *testing.T) {
	run := func(vals ...string) ([]string, string) {
		var seen []string
		h := RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = append([]string(nil), r.Header["X-Request-Id"]...)
		}))
		r := httptest.NewRequest("GET", "/", nil)
		for _, v := range vals {
			r.Header.Add("X-Request-Id", v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return seen, w.Header().Get("X-Request-Id")
	}

	if seen, resp := run("good-id-1"); len(seen) != 1 || seen[0] != "good-id-1" || resp != "good-id-1" {
		t.Errorf("single valid id: seen=%v resp=%q", seen, resp)
	}
	if seen, resp := run("good-id-1", strings.Repeat("x y", 20000)); len(seen) != 1 || seen[0] != "good-id-1" || resp != "good-id-1" {
		t.Errorf("valid first + huge second: seen has %d values, resp=%q", len(seen), resp)
	}
	if seen, resp := run("good-id-1", "good-id-2", "good-id-3"); len(seen) != 1 || seen[0] != resp || resp != "good-id-1" {
		t.Errorf("several valid values: seen=%v resp=%q", seen, resp)
	}
	// An invalid first value is replaced by a fresh ID and nothing else survives.
	seen, resp := run("bad id", "good-id-2")
	if len(seen) != 1 || seen[0] != resp || resp == "bad id" || resp == "good-id-2" {
		t.Errorf("invalid first value: seen=%v resp=%q", seen, resp)
	}
}
