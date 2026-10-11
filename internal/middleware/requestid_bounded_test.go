package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// F3101: a client-supplied X-Request-ID is reflected in the response, sent
// upstream and logged; an unbounded or non-printable value must be replaced.
func TestRequestIDClientValueBounded(t *testing.T) {
	h := RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	do := func(id string) string {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Request-ID", id)
		h.ServeHTTP(rec, req)
		return rec.Header().Get("X-Request-ID")
	}
	for _, ok := range []string{"abc-123", "01a12ab4-5fdf-71d4-bba5-dc40f7bed6da", strings.Repeat("a", 128)} {
		if got := do(ok); got != ok {
			t.Errorf("valid id %q rewritten to %q", ok, got)
		}
	}
	for _, bad := range []string{strings.Repeat("a", 129), strings.Repeat("A", 100000), "has space", "ctl\x01", "caf\xc3\xa9"} {
		got := do(bad)
		if got == bad || !validRequestID(got) || len(got) != 36 {
			t.Errorf("invalid id (len %d) not replaced: %q", len(bad), got)
		}
	}
}
