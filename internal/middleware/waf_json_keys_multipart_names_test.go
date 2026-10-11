package middleware

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/logger"
)

// F4900/F4901: object keys in a JSON body and field names in a multipart body
// are request data the application reads, but only values were scanned, while
// the urldecoded branch scans keys and values alike.
func TestWAFScansJSONKeysAndMultipartNames(t *testing.T) {
	guard := DomainWAFGuard(logger.New("error", "text"), nil, nil, nil)
	json := func(body string) bool {
		r := httptest.NewRequest(http.MethodPost, "/api/x", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		return guard(httptest.NewRecorder(), r)
	}
	multi := func(field, value string) bool {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormField(field)
		fw.Write([]byte(value))
		mw.Close()
		r := httptest.NewRequest(http.MethodPost, "/up", &buf)
		r.Header.Set("Content-Type", mw.FormDataContentType())
		return guard(httptest.NewRecorder(), r)
	}
	const payload = "1 UNION SELECT password FROM users"

	// Controls: payload in a value is blocked, benign bodies pass.
	if json(`{"q":"` + payload + `"}`) {
		t.Error("control: JSON value payload allowed")
	}
	if !json(`{"name":"alice","tags":["a","b"]}`) {
		t.Error("control: benign JSON blocked")
	}
	if multi("q", payload) {
		t.Error("control: multipart value payload allowed")
	}
	if !multi("name", "alice") {
		t.Error("control: benign multipart blocked")
	}

	for _, body := range []string{
		`{"` + payload + `":"x"}`,
		`{"a":{"` + payload + `":1}}`,
		`[{"drop table users":true}]`,
	} {
		if json(body) {
			t.Errorf("JSON key payload allowed: %s", body)
		}
	}
	if multi(payload, "x") {
		t.Error("multipart field-name payload allowed")
	}
}
