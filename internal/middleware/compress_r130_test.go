package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// F18300: the gzip variant must not carry the identity variant's strong
// validator. Compress skips Range requests, so a client that resumes the gzip
// body with If-Range: <that ETag> would be handed a slice of the identity
// bytes — the strong validator vouches for a different byte sequence
// (RFC 9110 §8.8.3).
func TestCompressWeakensETagOfCompressedVariant(t *testing.T) {
	body := strings.Repeat("hello world ", 400)
	h := Compress(1024)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("ETag", `"abc"`)
		http.ServeContent(w, r, "a.txt", time.Time{}, strings.NewReader(body))
	}))

	get := func(ae string, extra map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/a.txt", nil)
		if ae != "" {
			req.Header.Set("Accept-Encoding", ae)
		}
		for k, v := range extra {
			req.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	// Control: an identity response is not rewritten.
	id := get("", nil)
	if id.Header().Get("Content-Encoding") != "" || id.Header().Get("ETag") != `"abc"` {
		t.Fatalf("control: identity response changed: CE=%q ETag=%q", id.Header().Get("Content-Encoding"), id.Header().Get("ETag"))
	}

	gz := get("gzip", nil)
	if gz.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("setup: expected gzip response, got CE=%q", gz.Header().Get("Content-Encoding"))
	}
	etag := gz.Header().Get("ETag")
	t.Logf("EXPECTED: weak validator on the gzip variant (W/...)")
	t.Logf("ACTUAL:   ETag=%q", etag)
	if !strings.HasPrefix(etag, "W/") {
		t.Fatalf("PROBLEM CONFIRMED: gzip variant carries strong ETag %q", etag)
	}

	// The validator the client holds must not turn a ranged resume into a
	// 206 slice of a different representation.
	resume := get("gzip", map[string]string{"Range": "bytes=10-", "If-Range": etag})
	if resume.Code == http.StatusPartialContent {
		t.Fatalf("PROBLEM CONFIRMED: If-Range with the gzip variant's ETag got a 206 identity slice")
	}

	// A weak validator still revalidates: If-None-Match with it is a match
	// under weak comparison, which ServeContent applies.
	nm := get("gzip", map[string]string{"If-None-Match": etag})
	if nm.Code != http.StatusNotModified {
		t.Fatalf("conditional GET with the weak validator: status %d, want 304", nm.Code)
	}

	// An already-weak validator is left as it is.
	hw := Compress(1024)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("ETag", `W/"xyz"`)
		_, _ = w.Write([]byte(body))
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()
	hw.ServeHTTP(rr, req)
	if got := rr.Header().Get("ETag"); got != `W/"xyz"` {
		t.Fatalf("weak ETag rewritten to %q", got)
	}
}

// F18301: Cache-Control: no-transform forbids an intermediary to change the
// representation (RFC 9111 §5.2.2.6). A reverse proxy domain relays backend
// responses through this middleware.
func TestCompressHonoursNoTransform(t *testing.T) {
	body := strings.Repeat("hello world ", 400)
	serve := func(cc string, split bool) *httptest.ResponseRecorder {
		h := Compress(1024)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			if cc != "" {
				w.Header().Set("Cache-Control", cc)
			}
			if split {
				// Below minSize at the first write, decided at Close.
				_, _ = w.Write([]byte(body[:200]))
				_, _ = w.Write([]byte(body[200:]))
				return
			}
			_, _ = w.Write([]byte(body))
		}))
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	// Control: an ordinary Cache-Control does not stop compression.
	if ce := serve("public, max-age=60", false).Header().Get("Content-Encoding"); ce != "gzip" {
		t.Fatalf("control: CE=%q, want gzip", ce)
	}
	// "no-transform-x" is a different directive.
	if ce := serve("no-transform-x", false).Header().Get("Content-Encoding"); ce != "gzip" {
		t.Fatalf("control: unrelated directive blocked compression, CE=%q", ce)
	}

	for _, cc := range []string{"no-transform", "public, No-Transform", "max-age=60,no-transform"} {
		for _, split := range []bool{false, true} {
			rr := serve(cc, split)
			t.Logf("EXPECTED: identity body for Cache-Control %q", cc)
			t.Logf("ACTUAL:   CE=%q len=%d", rr.Header().Get("Content-Encoding"), rr.Body.Len())
			if rr.Header().Get("Content-Encoding") != "" || rr.Body.String() != body {
				t.Fatalf("PROBLEM CONFIRMED: Cache-Control %q (split=%v) was transformed: CE=%q", cc, split, rr.Header().Get("Content-Encoding"))
			}
		}
	}
}
