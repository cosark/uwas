package admin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cpanelUploadarchive(t *testing.T) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(name, body string) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	add("cpmove-bob/userdata/main", "main_domain: cpanel-upload.example.com\n")
	add("cpmove-bob/homedir/public_html/index.html", "hi")
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func cpanelUploadpost(t *testing.T, s *Server, field string, data []byte) *httptest.ResponseRecorder {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile(field, "cpmove-bob.tar.gz")
	fw.Write(data)
	mw.Close()
	req := httptest.NewRequest("POST", "/api/v1/migrate/cpanel", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, withAdminContext(req))
	return rec
}

func TestCPanelImportUploadSurvivesUntilImport(t *testing.T) {
	s, _ := testServerWithRoot(t)
	// F4100: saveUploadedFile deleted the upload before the import opened it.
	// control: a request without the file is rejected for the right reason
	if rec := cpanelUploadpost(t, s, "other", []byte("x")); rec.Code != 400 {
		t.Fatalf("invalid proof: control status %d", rec.Code)
	}
	rec := cpanelUploadpost(t, s, "backup", cpanelUploadarchive(t))
	webRoot := s.config.Global.WebRoot
	_, statErr := os.Stat(filepath.Join(webRoot, "cpanel-upload.example.com", "public_html", "index.html"))
	if rec.Code != 200 || statErr != nil {
		t.Fatalf("F4100: status %d %s, stat=%v; want 200 and site files copied", rec.Code, strings.TrimSpace(rec.Body.String()), statErr)
	}
}
