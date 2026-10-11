package middleware

import (
	"bytes"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/logger"
)

// F16000: the per-domain WAF skips the body scan for XML, protobuf, gRPC, binary
// and GraphQL-over-JSON content types (real XML and binary bodies are not text
// the patterns are meant for). The type is a request header, so the same JSON
// attack was blocked as application/json and allowed when the client labelled
// it with one of those: an application that reads the raw body and json_decodes
// it ignores the label. A body that opens as JSON is now scanned as JSON
// whatever it is labelled; real XML and binary bodies still pass.

func jsonAttack() []byte { return []byte(`{"id":"` + wafAttack + `"}`) }

func jsonEscapedAttack() []byte {
	return []byte(`{"id":"1' \u0055NION\u0020SELECT password FROM users--"}`)
}

func soapAttack() []byte {
	return []byte(`<?xml version="1.0"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">` +
		`<soap:Body><GetUser><id>` + wafAttack + `</id></GetUser></soap:Body></soap:Envelope>`)
}

var skippedTypes = []string{
	"application/xml", "text/xml; charset=utf-8", "application/soap+xml", "application/atom+xml",
	"application/graphql+json", "application/x-protobuf", "application/octet-stream",
	"application/grpc", "application/grpc-web",
}

func TestWAFDoesNotLetTheClientHideJSONBehindAnotherType(t *testing.T) {
	for _, ct := range skippedTypes {
		for _, body := range []struct {
			name string
			b    []byte
		}{{"JSON attack", jsonAttack()}, {"JSON escapes", jsonEscapedAttack()},
			{"JSON behind whitespace", append([]byte(" \r\n\t"), jsonAttack()...)}} {
			t.Run(ct+"/"+body.name, func(t *testing.T) {
				if wafAllows(t, "POST", ct, body.b, nil) {
					t.Errorf("a JSON attack labelled %q was let through", ct)
				}
			})
		}
	}
}

func TestWAFStillPassesRealXMLAndBinaryBodies(t *testing.T) {
	cases := []struct {
		name string
		ct   string
		body []byte
	}{
		// Real XML is not scanned (08a2c2af): XML webhooks carry SQL-like text.
		{"SOAP with SQL text", "application/xml", soapAttack()},
		{"SOAP over text/xml", "text/xml; charset=utf-8", soapAttack()},
		{"SOAP over soap+xml", "application/soap+xml", soapAttack()},
		{"XML over a +xml type", "application/atom+xml", soapAttack()},
		{"benign SVG", "image/svg+xml", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><circle r="4"/></svg>`)},
		{"binary upload", "application/octet-stream", append([]byte{0x00, 0x01, 0x02, 0xff, 0xfe}, []byte("PK\x03\x04 data")...)},
		{"protobuf frame", "application/x-protobuf", []byte{0x0a, 0x05, 'h', 'e', 'l', 'l', 'o', 0x10, 0x2a}},
		{"SQL dump uploaded as a file", "application/octet-stream", []byte("-- dump\nDROP TABLE IF EXISTS t;\nCREATE TABLE t (id int);\n")},
		{"gRPC frame", "application/grpc", []byte{0x00, 0x00, 0x00, 0x00, 0x05, 0x0a, 0x03, 'a', 'b', 'c'}},
		// A JSON-shaped body that is not an attack passes under every label.
		{"benign JSON as octet-stream", "application/octet-stream", []byte(`{"id":"42","name":"a union of workers"}`)},
		{"benign GraphQL request", "application/graphql+json", []byte(`{"query":"{ users { id name } }","variables":{"first":10}}`)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !wafAllows(t, "POST", c.ct, c.body, nil) {
				t.Errorf("%q body was blocked", c.ct)
			}
		})
	}
}

// Controls: the scans that already caught these.
func TestWAFPlainScansStillCatchTheAttack(t *testing.T) {
	for _, c := range []struct {
		name, ct string
		body     []byte
	}{
		{"JSON", "application/json", jsonAttack()},
		{"form", "application/x-www-form-urlencoded", []byte("id=" + wafAttack)},
		{"plain text", "text/plain", []byte(wafAttack)},
	} {
		t.Run(c.name, func(t *testing.T) {
			if wafAllows(t, "POST", c.ct, c.body, nil) {
				t.Error("let through")
			}
		})
	}
}

// A JSON-looking body is judged by what it is, so an oversized one cut at the
// scan limit still has its prefix scanned.
func TestWAFScansTheJSONPrefixOfAnOversizedMislabelledBody(t *testing.T) {
	body := append([]byte(`{"id":"`+wafAttack+`","pad":"`), []byte(strings.Repeat("a", 70<<10))...)
	if wafAllows(t, "POST", "application/octet-stream", body, nil) {
		t.Error("oversized JSON labelled octet-stream was let through unscanned")
	}
}

// A gRPC client sends its first frame and then waits for the response with the
// request stream still open. The WAF must neither wait for the rest of a
// 64 KiB window nor lose a byte of what it looked at.
func TestWAFDoesNotStallAStreamingBinaryBody(t *testing.T) {
	frame := []byte{0x00, 0x00, 0x00, 0x00, 0x05, 0x0a, 0x03, 'a', 'b', 'c'}
	pr, pw := io.Pipe()
	go func() { _, _ = pw.Write(frame) }() // the stream stays open afterwards
	t.Cleanup(func() { _ = pw.Close() })

	guard := DomainWAFGuard(logger.New("error", "text"), nil, nil, nil)
	r := httptest.NewRequest("POST", "/pkg.Service/Call", pr)
	r.Header.Set("Content-Type", "application/grpc")

	done := make(chan bool, 1)
	go func() { done <- guard(httptest.NewRecorder(), r) }()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("a gRPC frame was blocked")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the WAF waited on an open gRPC stream")
	}

	got := make([]byte, len(frame))
	if _, err := io.ReadFull(r.Body, got); err != nil {
		t.Fatalf("reading the body after the guard: %v", err)
	}
	if !bytes.Equal(got, frame) {
		t.Errorf("body after the guard = %v, want %v", got, frame)
	}
}

func TestSniffJSONStartReplaysEveryByte(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		json       bool
	}{
		{"object", `{"a":1}`, true},
		{"array", `[1,2]`, true},
		{"leading whitespace", " \r\n\t{\"a\":1}", true},
		{"text", "hello", false},
		{"empty", "", false},
		{"only whitespace", "   ", false},
		{"too much whitespace", strings.Repeat(" ", 100) + "{}", false},
		{"binary", "\x00\x01{", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc, got := sniffJSONStart(io.NopCloser(strings.NewReader(tc.body)))
			if got != tc.json {
				t.Errorf("json=%v, want %v", got, tc.json)
			}
			all, err := io.ReadAll(rc)
			if err != nil || string(all) != tc.body {
				t.Errorf("replayed %q (err %v), want %q", all, err, tc.body)
			}
		})
	}
}

// F16001: a JSON document labelled text/plain, a form type or nothing was
// scanned as raw text, which does not decode JSON string escapes; only
// application/json was caught.
func TestWAFDecodesJSONEscapesWhateverTheLabel(t *testing.T) {
	for _, ct := range []string{"text/plain", "application/x-www-form-urlencoded", "", "text/html", "application/json"} {
		t.Run("label "+ct, func(t *testing.T) {
			if wafAllows(t, "POST", ct, jsonEscapedAttack(), nil) {
				t.Errorf("JSON escapes labelled %q were let through", ct)
			}
		})
	}
	// Controls: prose and form text that merely starts oddly, or a JSON document
	// with nothing in it, pass.
	for _, c := range []struct{ name, ct, body string }{
		{"form field", "application/x-www-form-urlencoded", "a=1&b=%5Bx%5D"},
		{"bracketed prose", "text/plain", "[draft] a union of workers"},
		{"benign JSON as text", "text/plain", `{"note":"a union of workers","n":3}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if !wafAllows(t, "POST", c.ct, []byte(c.body), nil) {
				t.Errorf("%q was blocked", c.body)
			}
		})
	}
}
