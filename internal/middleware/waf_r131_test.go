package middleware

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/logger"
)

func wafR131Guard() func(http.ResponseWriter, *http.Request) bool {
	return DomainWAFGuard(logger.New("error", "text"), nil, nil, nil)
}

// F18700: several Content-Encoding header lines are one list (RFC 9110 5.3), and
// Node and friends join them before inflating. The guard read only the first
// line, so "identity" first and "gzip" second left a gzip body unscanned.
func TestWAFContentEncodingHeaderLinesAreJoined(t *testing.T) {
	guard := wafR131Guard()
	const attack = `{"q":"1 UNION SELECT password FROM users"}`
	send := func(lines ...string) bool {
		r := httptest.NewRequest("POST", "/api/x", bytes.NewReader(encodeGzip([]byte(attack))))
		r.Header.Set("Content-Type", "application/json")
		for _, l := range lines {
			r.Header.Add("Content-Encoding", l)
		}
		return guard(httptest.NewRecorder(), r)
	}
	if send("gzip") {
		t.Fatal("control: single gzip header attack allowed")
	}
	if send("identity, gzip") {
		t.Fatal("control: comma list attack allowed")
	}
	if send("identity", "gzip") {
		t.Fatal("EXPECTED: blocked; ACTUAL: allowed when Content-Encoding is split over two header lines")
	}
}

// F18701: SQL accepts more between two keywords than whitespace and /* */: a
// vertical tab (MySQL, SQLite), a "#" line comment (MySQL) and a "--" line
// comment all separate UNION from SELECT.
func TestWAFSQLSeparatorsCoverLineCommentsAndVT(t *testing.T) {
	guard := wafR131Guard()
	allowed := func(target string) bool {
		r := httptest.NewRequest("GET", target, nil)
		return guard(httptest.NewRecorder(), r)
	}
	if allowed("/p?id=1%20union%20select%20password%20from%20users") {
		t.Fatal("control: plain union select allowed")
	}
	for _, c := range []struct{ name, target string }{
		{"vertical tab", "/p?id=1%20union%0bselect%20password"},
		{"hash comment", "/p?id=1%20union%23x%0aselect%20password"},
		{"dash comment", "/p?id=1%20union--%0aselect%20password"},
		{"dash space comment", "/p?id=1%20union--%20x%0aselect%20password"},
		{"insert into vt", "/p?q=insert%0binto%20t"},
		{"semicolon vt update", "/p?q=1;%0bupdate%20t%20set"},
		{"sleep vt", "/p?q=sleep%0b(5)"},
	} {
		if allowed(c.target) {
			t.Errorf("%s: EXPECTED blocked; ACTUAL allowed (%s)", c.name, c.target)
		}
	}
	// Controls: prose that merely contains the words stays allowed.
	for _, target := range []string{
		"/p?q=european+union+selected+members",
		"/p?q=trade-union%0aselected",
		"/p?q=a;%20b+c",
	} {
		if !allowed(target) {
			t.Errorf("control: benign %s blocked", target)
		}
	}
}

// F18702: a gzip body under an XML/binary label was judged on its compressed
// bytes, so the JSON sniff (F16000) never saw the '{' a decoding backend does.
func TestWAFSniffsJSONThroughContentEncoding(t *testing.T) {
	guard := wafR131Guard()
	const attack = `{"q":"1 UNION SELECT password FROM users"}`
	send := func(ct string, body []byte, enc string) (bool, []byte) {
		r := httptest.NewRequest("POST", "/api/x", bytes.NewReader(body))
		r.Header.Set("Content-Type", ct)
		if enc != "" {
			r.Header.Set("Content-Encoding", enc)
		}
		ok := guard(httptest.NewRecorder(), r)
		rest, _ := io.ReadAll(r.Body)
		return ok, rest
	}
	if ok, _ := send("application/octet-stream", []byte(attack), ""); ok {
		t.Fatal("control: plain mislabelled JSON allowed")
	}
	if ok, _ := send("application/json", encodeGzip([]byte(attack)), "gzip"); ok {
		t.Fatal("control: gzip JSON under application/json allowed")
	}
	gz := encodeGzip([]byte(attack))
	if ok, _ := send("application/octet-stream", gz, "gzip"); ok {
		t.Error("EXPECTED: blocked; ACTUAL: gzip JSON labelled octet-stream allowed")
	}
	// Real XML and binary stay unscanned, compressed or not, and the body
	// reaches the handler unchanged.
	xml := []byte(`<?xml version="1.0"?><q>union select</q>`)
	for _, body := range [][]byte{xml, encodeGzip(xml)} {
		enc := ""
		if !bytes.Equal(body, xml) {
			enc = "gzip"
		}
		ok, rest := send("application/xml", body, enc)
		if !ok {
			t.Errorf("control: xml (enc=%q) blocked", enc)
		}
		if !bytes.Equal(rest, body) {
			t.Errorf("body altered for xml (enc=%q)", enc)
		}
	}
	ok, rest := send("application/octet-stream", gz, "gzip")
	_ = ok
	if !bytes.Equal(rest, gz) {
		t.Error("compressed body not replayed unchanged")
	}
}

// F18703: only a part whose Content-Disposition is "form-data; name=..." had its
// value scanned. A part without a name, or with another disposition type, was
// skipped although lenient multipart parsers accept it as a field.
func TestWAFMultipartScansPartsWithoutFormName(t *testing.T) {
	guard := wafR131Guard()
	const attack = "1 UNION SELECT password FROM users"
	build := func(disp string) (*http.Request, string) {
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		h := textproto.MIMEHeader{}
		if disp != "" {
			h.Set("Content-Disposition", disp)
		}
		p, _ := w.CreatePart(h)
		p.Write([]byte(attack))
		w.Close()
		r := httptest.NewRequest("POST", "/up", &b)
		r.Header.Set("Content-Type", w.FormDataContentType())
		return r, b.String()
	}
	r, _ := build(`form-data; name="q"`)
	if guard(httptest.NewRecorder(), r) {
		t.Fatal("control: form-data field attack allowed")
	}
	for _, disp := range []string{
		`attachment; name="q"`,
		`form-data`,
		`form-data; filename="a.txt"`,
		``,
	} {
		r, _ := build(disp)
		if guard(httptest.NewRecorder(), r) {
			t.Errorf("disposition %q: EXPECTED blocked; ACTUAL allowed", disp)
		}
	}
	// Control: benign nameless part passes.
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	p, _ := w.CreatePart(textproto.MIMEHeader{"Content-Disposition": {"attachment"}})
	p.Write([]byte("hello"))
	w.Close()
	r2 := httptest.NewRequest("POST", "/up", &b)
	r2.Header.Set("Content-Type", w.FormDataContentType())
	if !guard(httptest.NewRecorder(), r2) {
		t.Error("control: benign nameless part blocked")
	}
}

// Characterisation: every built-in rule stays linear on a 64 KiB hostile input.
// RE2 has no catastrophic backtracking; the numbers below document that and
// fail only on a gross regression (baseline: about 0.3 s in total without -race).
func TestWAFRulesLinearOnLargeInput(t *testing.T) {
	inputs := map[string]string{
		"union-spaces": strings.Repeat("union ", 11000),
		"comment-open": "union " + strings.Repeat("/*", 32000),
		"or-numbers":   strings.Repeat("' or 1 ", 9000),
		"dashes":       strings.Repeat("-- ", 21000),
		"hash-lines":   "union" + strings.Repeat("#x\n", 21000),
	}
	for name, in := range inputs {
		start := time.Now()
		matchWAFURL(in, in)
		matchWAFBody(in, in)
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("%s: %v on 64 KiB input", name, d)
		}
	}
}
