package htaccess

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"unicode/utf16"
)

func accessOf(t *testing.T, raw []byte) (*RuleSet, AccessDecision, error) {
	t.Helper()
	ds, err := Parse(bytes.NewReader(raw))
	if err != nil {
		return nil, AccessUnset, err
	}
	rs := Convert(ds)
	return rs, rs.AccessForMethod(net.ParseIP("198.51.100.7"), "GET"), nil
}

// F7300: a UTF-8 BOM must not hide the first directive of the file.
func TestParseStripsUTF8BOM(t *testing.T) {
	if _, d, err := accessOf(t, []byte("\xef\xbb\xbfRequire all denied\n")); err != nil || d != AccessDenied {
		t.Errorf("BOM + Require all denied: decision=%v err=%v, want denied", d, err)
	}
	rs, _, err := accessOf(t, []byte("\xef\xbb\xbf<FilesMatch \"\\.env$\">\nRequire all denied\n</FilesMatch>\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !FilesMatchDenies(rs, ".env") {
		t.Error("BOM before <FilesMatch>: .env not denied")
	}
	if FilesMatchDenies(rs, "index.html") {
		t.Error("BOM before <FilesMatch>: index.html denied")
	}
	// Control: no BOM behaves the same, and a BOM-less file is untouched.
	if _, d, _ := accessOf(t, []byte("Require all denied\n")); d != AccessDenied {
		t.Errorf("control without BOM: decision=%v", d)
	}
	// Only a leading BOM is a BOM; one in the middle is not stripped.
	ds, err := Parse(strings.NewReader("Header set X-A 1\n\ufeffRequire all denied\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 2 || ds[1].Name == "Require" {
		t.Errorf("mid-file BOM should stay part of the name, got %+v", ds)
	}
}

// F7301: a file that is not plain text must be refused, not parsed into
// directives whose names are garbage and so silently dropped.
func TestParseRejectsUTF16AndNUL(t *testing.T) {
	var u16 bytes.Buffer
	u16.Write([]byte{0xFF, 0xFE})
	for _, c := range utf16.Encode([]rune("Require all denied\r\n")) {
		u16.WriteByte(byte(c))
		u16.WriteByte(byte(c >> 8))
	}
	for name, raw := range map[string][]byte{
		"utf16le-bom": u16.Bytes(),
		"nul-inside":  []byte("Header set X-A 1\nRequire all\x00 denied\n"),
	} {
		if _, err := Parse(bytes.NewReader(raw)); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
	// Control: CRLF plain text still parses.
	if _, d, err := accessOf(t, []byte("Require all denied\r\n")); err != nil || d != AccessDenied {
		t.Errorf("CRLF control: decision=%v err=%v", d, err)
	}
}
