package admin

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

// F10100: a webhook's custom header values (typically Authorization or an API
// key) were returned in the clear by every read surface while the webhook's
// secret next to them was masked.
func TestWebhookHeaderValuesMaskedOnEveryReadSurface(t *testing.T) {
	const hv = "Bearer HEADERSECRET-1234567890"
	const url = "https://hooks.example.com/ingest"
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "uwas.yaml")
	os.WriteFile(cfgPath, []byte("global:\n  webhooks:\n    - url: \""+url+"\"\n      secret: CONTROLSECRET\n      headers:\n        Authorization: \""+hv+"\"\n        X-Team: ops\n"), 0o644)

	s := testServer()
	s.SetConfigPath(cfgPath)
	s.config.Global.Webhooks = []config.WebhookConfig{{
		URL: url, Secret: "CONTROLSECRET", Enabled: true,
		Headers: map[string]string{"Authorization": hv, "X-Team": "ops"},
	}}

	for name, path := range map[string]string{
		"webhooks":      "/api/v1/webhooks",
		"notifications": "/api/v1/settings/notifications",
		"export":        "/api/v1/config/export",
		"raw":           "/api/v1/config/raw",
	} {
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		body := rec.Body.String()
		if name == "raw" {
			var raw map[string]string
			json.Unmarshal(rec.Body.Bytes(), &raw)
			body = raw["content"]
		}
		if strings.Contains(body, "CONTROLSECRET") {
			t.Errorf("%s: webhook secret visible (control)", name)
		}
		if strings.Contains(body, "HEADERSECRET") {
			t.Errorf("%s: webhook header value visible", name)
		}
	}
	// reading must not have masked the live config
	if got := s.config.Global.Webhooks[0].Headers["Authorization"]; got != hv {
		t.Fatalf("live header value changed to %q", got)
	}
}

// Saving back what a read returned must not overwrite the real header value
// with the mask, while an explicit change still takes effect.
func TestWebhookHeaderMaskedValueIsNotPersisted(t *testing.T) {
	const hv = "Bearer HEADERSECRET-1234567890"
	const url = "https://hooks.example.com/ingest"
	s := testServer()
	s.config.Global.Webhooks = []config.WebhookConfig{{
		URL: url, Enabled: true,
		Headers: map[string]string{"Authorization": hv, "X-Team": "ops"},
	}}

	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/settings/notifications", nil))
	var got struct {
		Webhooks []config.WebhookConfig `json:"webhooks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Webhooks) != 1 || got.Webhooks[0].Headers["Authorization"] == hv || got.Webhooks[0].Headers["Authorization"] == "" {
		t.Fatalf("notifications GET header = %+v, want a mask", got.Webhooks)
	}

	body, _ := json.Marshal(map[string]any{"webhooks": got.Webhooks})
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest("PUT", "/api/v1/settings/notifications", strings.NewReader(string(body))))
	if rec.Code != 200 {
		t.Fatalf("PUT notifications = %d: %s", rec.Code, rec.Body.String())
	}
	if h := s.config.Global.Webhooks[0].Headers; h["Authorization"] != hv || h["X-Team"] != "ops" {
		t.Fatalf("round trip changed headers to %+v", h)
	}

	// an explicit change still goes through
	got.Webhooks[0].Headers["Authorization"] = "Bearer NEW"
	body, _ = json.Marshal(map[string]any{"webhooks": got.Webhooks})
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest("PUT", "/api/v1/settings/notifications", strings.NewReader(string(body))))
	if s.config.Global.Webhooks[0].Headers["Authorization"] != "Bearer NEW" {
		t.Fatalf("explicit change ignored: %+v", s.config.Global.Webhooks[0].Headers)
	}
}

// The raw editor shows webhook header values masked and restores them on save.
func TestWebhookHeaderRawEditorRoundTrip(t *testing.T) {
	const hv = "Bearer HEADERSECRET-1234567890"
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "uwas.yaml")
	orig := "global:\n  webhooks:\n    - url: \"https://hooks.example.com/ingest\"\n      headers:\n        Authorization: \"" + hv + "\"\n        X-Team: ops\n"
	os.WriteFile(cfgPath, []byte(orig), 0o600)
	s := testServer()
	s.SetConfigPath(cfgPath)

	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/config/raw", nil))
	var raw map[string]string
	json.Unmarshal(rec.Body.Bytes(), &raw)
	if strings.Contains(raw["content"], "HEADERSECRET") {
		t.Fatalf("raw editor shows the header value:\n%s", raw["content"])
	}
	if !strings.Contains(raw["content"], "Authorization") {
		t.Fatalf("raw editor lost the header name:\n%s", raw["content"])
	}
	body, _ := json.Marshal(map[string]string{"content": raw["content"]})
	rec = httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/v1/config/raw", strings.NewReader(string(body)))
	s.mux.ServeHTTP(rec, req)
	saved, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(saved), hv) {
		t.Fatalf("save (HTTP %d) overwrote the header value:\n%s", rec.Code, saved)
	}
	if strings.Contains(string(saved), "********") {
		t.Fatalf("mask written to disk:\n%s", saved)
	}
}

// The audit log is readable by every admin and kept on disk; a webhook URL
// carries its credential in the path or query.
func TestWebhookAuditEntriesDoNotCarryTheTokenURL(t *testing.T) {
	const tok = "AUDITTOKEN-1234567890"
	s := testServer()
	s.SetConfigPath(filepath.Join(t.TempDir(), "uwas.yaml"))
	body := `{"url":"https://93.184.216.34/services/T0/B0/` + tok + `?key=` + tok + `"}`
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/webhooks", strings.NewReader(body)))
	if rec.Code != 200 {
		t.Skipf("webhook create = %d: %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/audit", nil))
	if strings.Contains(rec.Body.String(), tok) {
		t.Errorf("audit log carries the webhook token: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "93.184.216.34") {
		t.Errorf("audit entry lost the webhook host: %s", rec.Body.String())
	}
}
