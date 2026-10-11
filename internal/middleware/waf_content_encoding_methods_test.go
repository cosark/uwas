package middleware

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/uwaserver/uwas/internal/logger"
)

func encodeGzip(s []byte) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write(s)
	w.Close()
	return b.Bytes()
}

func encodeZlib(s []byte) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write(s)
	w.Close()
	return b.Bytes()
}

// F10000/F10001: the body scan read the raw bytes, so a Content-Encoding: gzip
// payload (which Express-style upstreams inflate) was invisible to it, and
// only POST/PUT/PATCH bodies were scanned at all, so a DELETE or GET body
// carrying the same payload was never looked at.
func TestWAFBodyScanSeesContentEncodingAndEveryMethod(t *testing.T) {
	guard := DomainWAFGuard(logger.New("error", "text"), nil, nil, nil)
	const attack = `{"q":"1 UNION SELECT password FROM users"}`
	const benign = `{"name":"alice"}`
	allowed := func(method, enc string, body []byte) (bool, []byte) {
		r := httptest.NewRequest(method, "/api/x", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if enc != "" {
			r.Header.Set("Content-Encoding", enc)
		}
		ok := guard(httptest.NewRecorder(), r)
		rest, _ := io.ReadAll(r.Body)
		return ok, rest
	}

	// Controls: a plain attack is blocked, benign bodies pass in every shape.
	if ok, _ := allowed("POST", "", []byte(attack)); ok {
		t.Fatal("control: plain attack allowed")
	}
	for _, c := range []struct {
		m, enc string
		body   []byte
	}{
		{"POST", "", []byte(benign)},
		{"POST", "gzip", encodeGzip([]byte(benign))},
		{"DELETE", "", []byte(benign)},
		{"GET", "", nil},
	} {
		if ok, _ := allowed(c.m, c.enc, c.body); !ok {
			t.Errorf("control: benign %s %q blocked", c.m, c.enc)
		}
	}

	for _, c := range []struct {
		name, m, enc string
		body         []byte
	}{
		{"gzip", "POST", "gzip", encodeGzip([]byte(attack))},
		{"x-gzip", "POST", "x-gzip", encodeGzip([]byte(attack))},
		{"deflate zlib", "PUT", "deflate", encodeZlib([]byte(attack))},
		{"stacked", "POST", "gzip, gzip", encodeGzip(encodeGzip([]byte(attack)))},
		{"delete plain", "DELETE", "", []byte(attack)},
		{"get plain", "GET", "", []byte(attack)},
	} {
		if ok, _ := allowed(c.m, c.enc, c.body); ok {
			t.Errorf("%s: attack allowed", c.name)
		}
	}

	// The scan must not change what the application receives.
	enc := encodeGzip([]byte(benign))
	ok, rest := allowed("POST", "gzip", enc)
	if !ok || !bytes.Equal(rest, enc) {
		t.Errorf("downstream body altered: ok=%v equal=%v", ok, bytes.Equal(rest, enc))
	}
}

// A coding the guard cannot undo (br, zstd) or a corrupt stream must not panic
// or be blocked on size alone, and a decompression bomb stays bounded by the
// scan window.
func TestWAFBodyScanEncodingEdgeCases(t *testing.T) {
	guard := DomainWAFGuard(logger.New("error", "text"), nil, nil, nil)
	run := func(enc string, body []byte) bool {
		r := httptest.NewRequest("POST", "/api/x", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Content-Encoding", enc)
		return guard(httptest.NewRecorder(), r)
	}
	if !run("br", []byte("\x1b\x00\x00opaque")) {
		t.Error("unsupported coding blocked")
	}
	if !run("gzip", []byte("not gzip at all")) {
		t.Error("corrupt gzip stream blocked")
	}
	if !run("identity", []byte(`{"a":"b"}`)) {
		t.Error("identity coding blocked")
	}
	bomb := encodeGzip(bytes.Repeat([]byte{'a'}, 4<<20))
	if len(bomb) > maxBodyScan {
		t.Fatalf("test bomb too large: %d", len(bomb))
	}
	if !run("gzip", bomb) {
		t.Error("benign decompression bomb blocked")
	}
}
