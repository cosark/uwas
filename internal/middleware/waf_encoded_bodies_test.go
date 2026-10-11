package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/uwaserver/uwas/internal/logger"
)

const wafAttack = "1' UNION SELECT password FROM users--"

// wafAllows runs one request through the per-domain WAF and reports whether it
// was let through to the application.
func wafAllows(t *testing.T, method, ct string, body []byte, hdr map[string]string) bool {
	t.Helper()
	guard := DomainWAFGuard(logger.New("error", "text"), nil, nil, nil)
	r := httptest.NewRequest(method, "/submit", bytes.NewReader(body))
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return guard(httptest.NewRecorder(), r)
}

func utf16Bytes(s string, bigEndian, bom bool) []byte {
	u := utf16.Encode([]rune(s))
	var out []byte
	if bom {
		if bigEndian {
			out = append(out, 0xFE, 0xFF)
		} else {
			out = append(out, 0xFF, 0xFE)
		}
	}
	for _, w := range u {
		if bigEndian {
			out = append(out, byte(w>>8), byte(w))
		} else {
			out = append(out, byte(w), byte(w>>8))
		}
	}
	return out
}

// F15700: Go's multipart reader decodes a part marked
// "Content-Transfer-Encoding: quoted-printable" and stops at the first invalid
// "=" sequence, while PHP and most backends hand the part over undecoded. The
// payload behind the invalid sequence was never scanned.
func TestWAFMultipartQuotedPrintablePartIsStillScanned(t *testing.T) {
	multipart := func(cte, value string) []byte {
		var b strings.Builder
		b.WriteString("--B\r\nContent-Disposition: form-data; name=\"q\"\r\n")
		if cte != "" {
			b.WriteString("Content-Transfer-Encoding: " + cte + "\r\n")
		}
		b.WriteString("\r\n" + value + "\r\n--B--\r\n")
		return []byte(b.String())
	}
	ct := "multipart/form-data; boundary=B"

	// Controls: the same payload is blocked without the encoding header, and a
	// harmless quoted-printable part passes.
	if wafAllows(t, "POST", ct, multipart("", wafAttack), nil) {
		t.Fatal("control: plain multipart attack was allowed")
	}
	if !wafAllows(t, "POST", ct, multipart("quoted-printable", "hello=20world"), nil) {
		t.Fatal("control: harmless quoted-printable part was blocked")
	}

	for name, value := range map[string]string{
		"invalid escape first":     "=ZZ" + wafAttack,
		"invalid escape mid":       "abc=Z" + wafAttack,
		"soft break then payload":  "=\r\n" + wafAttack,
		"valid escape then attack": "=41" + wafAttack,
	} {
		if wafAllows(t, "POST", ct, multipart("quoted-printable", value), nil) {
			t.Errorf("%s: payload behind a quoted-printable part was allowed", name)
		}
	}
}

// F15701: a JSON body sent as UTF-16 is decoded by charset-aware backends
// (Node's body-parser accepts any utf-* charset) but the WAF only scanned the
// raw bytes, where every character is followed by a NUL.
func TestWAFJSONUTF16BodyIsScanned(t *testing.T) {
	doc := `{"q":"` + wafAttack + `"}`
	harmless := `{"q":"hello world"}`

	if wafAllows(t, "POST", "application/json", []byte(doc), nil) {
		t.Fatal("control: UTF-8 JSON attack was allowed")
	}
	if !wafAllows(t, "POST", "application/json; charset=utf-16le", utf16Bytes(harmless, false, false), nil) {
		t.Fatal("control: harmless UTF-16 JSON was blocked")
	}

	cases := []struct {
		name, ct string
		body     []byte
	}{
		{"utf-16le charset", "application/json; charset=utf-16le", utf16Bytes(doc, false, false)},
		{"utf-16be charset", "application/json; charset=utf-16be", utf16Bytes(doc, true, false)},
		{"utf-16 with BOM, no charset", "application/json", utf16Bytes(doc, false, true)},
		{"utf-16 BE BOM, no charset", "application/json", utf16Bytes(doc, true, true)},
		{"utf-32le BOM", "application/json", utf32Bytes(doc, false, true)},
		{"utf-32be no BOM", "application/json", utf32Bytes(doc, true, false)},
		{"utf-16le, leading whitespace", "application/json", utf16Bytes("  \n"+doc, false, false)},
		{"utf-16le +json media type", "application/vnd.api+json", utf16Bytes(doc, false, false)},
	}
	for _, c := range cases {
		if wafAllows(t, "POST", c.ct, c.body, nil) {
			t.Errorf("%s: UTF-16 payload was allowed", c.name)
		}
	}
}

func utf32Bytes(s string, bigEndian, bom bool) []byte {
	var out []byte
	put := func(r rune) {
		v := uint32(r)
		if bigEndian {
			out = append(out, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
		} else {
			out = append(out, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
		}
	}
	if bom {
		put(0xFEFF)
	}
	for _, r := range s {
		put(r)
	}
	return out
}

// Decoding is only for JSON: a form body is not decoded by PHP or Express, so
// a UTF-16 form body stays opaque, and nothing about plain UTF-8 changes.
func TestWideJSONDetectionLeavesOtherBodiesAlone(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty":        nil,
		"one byte":     []byte("{"),
		"utf-8 json":   []byte(`{"q":"hello"}`),
		"binary blob":  {0x00, 0x01, 0x02, 0x03, 0x04},
		"utf-8 emoji":  []byte(`{"q":"` + "\U0001F600" + `"}`),
		"latin1 bytes": {'{', 0xE9, '}', 0xE9},
	} {
		if dec, ok := decodeWideJSON(b); ok {
			t.Errorf("%s: decoded as wide JSON: %q", name, dec)
		}
	}
	if !wafAllows(t, "POST", "application/x-www-form-urlencoded; charset=utf-16le", utf16Bytes("q=hello", false, false), nil) {
		t.Error("harmless UTF-16 form body was blocked")
	}
}

var _ = http.StatusOK

// F15702: json.Unmarshal into interface{} keeps only the last of a duplicated
// key, so the value in front of it was never scanned. Parsers disagree on which
// duplicate wins (RapidJSON's FindMember returns the first), so every string in
// the document is inspected, not just the survivor.
func TestWAFJSONDuplicateKeysAreAllScanned(t *testing.T) {
	benign := `{"q":"hello","r":"world"}`
	if !wafAllows(t, "POST", "application/json", []byte(benign), nil) {
		t.Fatal("control: harmless JSON was blocked")
	}
	if wafAllows(t, "POST", "application/json", []byte(`{"q":"`+wafAttack+`"}`), nil) {
		t.Fatal("control: single-key attack was allowed")
	}
	for name, doc := range map[string]string{
		"attack in the first duplicate":  `{"q":"` + wafAttack + `","q":"hello"}`,
		"attack in the middle duplicate": `{"q":"a","q":"` + wafAttack + `","q":"b"}`,
		"duplicate inside a nested obj":  `{"o":{"q":"` + wafAttack + `","q":"x"}}`,
		"duplicate inside an array item": `[{"q":"` + wafAttack + `","q":"x"}]`,
	} {
		if wafAllows(t, "POST", "application/json", []byte(doc), nil) {
			t.Errorf("%s: shadowed duplicate was allowed", name)
		}
	}
}
