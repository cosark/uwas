package admin

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F9820: alerting.webhook_url is an incoming-webhook URL whose path or query is
// the credential, exactly like slack_url, yet every read surface showed it in
// the clear while slack_url was masked.
func TestAlertingWebhookURLMaskedOnEveryReadSurface(t *testing.T) {
	const tok = "SECRETTOKEN-1234567890"
	const slack = "https://hooks.slack.com/services/T0/B0/CONTROLSLACK"
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "uwas.yaml")
	os.WriteFile(cfgPath, []byte("global:\n  alerting:\n    webhook_url: \"https://chat.example/hooks/"+tok+"\"\n    slack_url: \""+slack+"\"\n"), 0o644)

	s := testServer()
	s.SetConfigPath(cfgPath)
	s.config.Global.Alerting.WebhookURL = "https://chat.example/hooks/" + tok
	s.config.Global.Alerting.SlackURL = slack

	for name, path := range map[string]string{
		"settings":      "/api/v1/settings",
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
		if strings.Contains(body, "CONTROLSLACK") {
			t.Errorf("%s: slack_url visible (control)", name)
		}
		if strings.Contains(body, tok) {
			t.Errorf("%s: webhook_url token visible", name)
		}
	}
}

// Saving back what a read returned must not overwrite the real URL with the mask.
func TestAlertingWebhookURLMaskedValueIsNotPersisted(t *testing.T) {
	const live = "https://chat.example/hooks/SECRETTOKEN-1234567890"
	s := testServer()
	s.config.Global.Alerting.WebhookURL = live

	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/settings/notifications", nil))
	var got struct {
		Alerting map[string]any `json:"alerting"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	masked, _ := got.Alerting["WebhookURL"].(string)
	if masked == "" || masked == live {
		t.Fatalf("notifications GET webhook_url = %q, want a mask", masked)
	}

	// notifications round trip
	body, _ := json.Marshal(map[string]any{"alerting": map[string]any{"Enabled": true, "WebhookURL": masked}})
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest("PUT", "/api/v1/settings/notifications", strings.NewReader(string(body))))
	if rec.Code != 200 {
		t.Fatalf("PUT notifications = %d: %s", rec.Code, rec.Body.String())
	}
	if s.config.Global.Alerting.WebhookURL != live {
		t.Fatalf("notifications save replaced the URL with %q", s.config.Global.Alerting.WebhookURL)
	}

	// settings round trip
	body, _ = json.Marshal(map[string]any{"global.alerting.webhook_url": masked})
	rec = httptest.NewRecorder()
	s.handleSettingsPut(rec, withAdminContext(httptest.NewRequest("PUT", "/api/v1/settings", strings.NewReader(string(body)))))
	if rec.Code != 200 {
		t.Fatalf("PUT settings = %d: %s", rec.Code, rec.Body.String())
	}
	if s.config.Global.Alerting.WebhookURL != live {
		t.Fatalf("settings save replaced the URL with %q", s.config.Global.Alerting.WebhookURL)
	}

	// a real change still goes through
	body, _ = json.Marshal(map[string]any{"global.alerting.webhook_url": "https://other.example/new"})
	rec = httptest.NewRecorder()
	s.handleSettingsPut(rec, withAdminContext(httptest.NewRequest("PUT", "/api/v1/settings", strings.NewReader(string(body)))))
	if s.config.Global.Alerting.WebhookURL != "https://other.example/new" {
		t.Fatalf("explicit change ignored: %q", s.config.Global.Alerting.WebhookURL)
	}
}
