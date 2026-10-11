package admin

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// F13700: PUT /api/v1/settings only acts on keys named in its switch, and it
// answered 200 "saved, updated: N" for every other key without applying it.
// The dashboard's settings page sends the white-label branding, OAuth and
// ACME DNS-credential fields through this route, so an operator who typed a
// Cloudflare token or a panel name saw "Saved" while nothing was stored; a
// misspelled key ("global.rate_limt.requests") behaved the same way.
func TestSettingsPutPersistsEveryDashboardKey(t *testing.T) {
	s := settingsTestServer(t)

	putSettings(t, s, `{
		"global.admin.branding.name": "Acme Panel",
		"global.admin.branding.logo_url": "https://example.com/logo.svg",
		"global.admin.branding.favicon_url": "https://example.com/favicon.ico",
		"global.admin.branding.primary_color": "#112233",
		"global.admin.branding.footer_text": "Hosted by Acme",
		"global.admin.oauth.enabled": true,
		"global.admin.oauth.google_client_id": "gid",
		"global.admin.oauth.google_client_secret": "gsecret-value",
		"global.admin.oauth.github_client_id": "ghid",
		"global.admin.oauth.github_client_secret": "ghsecret-value",
		"global.admin.oauth.allowed_emails": "a@example.com, b@example.com",
		"global.acme.dns_credentials.api_token": "cf-token-value",
		"global.acme.dns_credentials.api_key": "cf-key-value",
		"global.acme.dns_credentials.access_key_id": "AKIAEXAMPLE",
		"global.acme.dns_credentials.secret_access_key": "aws-secret-value"
	}`)

	g := s.config.Global
	if g.Admin.Branding.Name != "Acme Panel" || g.Admin.Branding.LogoURL != "https://example.com/logo.svg" ||
		g.Admin.Branding.FaviconURL != "https://example.com/favicon.ico" ||
		g.Admin.Branding.PrimaryColor != "#112233" || g.Admin.Branding.FooterText != "Hosted by Acme" {
		t.Errorf("branding fields were accepted but not stored: %+v", g.Admin.Branding)
	}
	o := g.Admin.OAuth
	if !o.Enabled || o.GoogleID != "gid" || o.GoogleSecret != "gsecret-value" ||
		o.GitHubID != "ghid" || o.GitHubSecret != "ghsecret-value" ||
		len(o.AllowedEmails) != 2 || o.AllowedEmails[0] != "a@example.com" || o.AllowedEmails[1] != "b@example.com" {
		t.Errorf("oauth fields were accepted but not stored: %+v", o)
	}
	c := g.ACME.DNSCredentials
	if c["api_token"] != "cf-token-value" || c["api_key"] != "cf-key-value" ||
		c["access_key_id"] != "AKIAEXAMPLE" || c["secret_access_key"] != "aws-secret-value" {
		t.Errorf("ACME DNS credentials were accepted but not stored: %v", c)
	}

	// The panel renders what GET returns; secrets come back masked, never raw.
	body := settingsBody(t, s)
	if body["global.admin.branding.name"] != "Acme Panel" {
		t.Errorf("GET branding.name = %v, want the saved value", body["global.admin.branding.name"])
	}
	for _, k := range []string{
		"global.admin.oauth.google_client_secret", "global.admin.oauth.github_client_secret",
		"global.acme.dns_credentials.api_token", "global.acme.dns_credentials.secret_access_key",
	} {
		v, _ := body[k].(string)
		if v == "" || strings.Contains(v, "secret-value") || strings.Contains(v, "token-value") {
			t.Errorf("GET %s = %q: must be present and masked", k, v)
		}
	}
}

func TestSettingsPutRejectsUnknownKeys(t *testing.T) {
	s := settingsTestServer(t)
	before := s.config.Global.RateLimit.Requests
	beforeWindow := s.config.Global.RateLimit.Window.String()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/v1/settings",
		strings.NewReader(`{"global.rate_limt.requests": 5, "global.rate_limit.window": "30s", "global.log_level": "warn"}`))
	req.RemoteAddr = "10.0.0.1:1234"
	s.handleSettingsPut(rec, withAdminContext(req))

	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400 for a misspelled key; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "global.rate_limt.requests") {
		t.Errorf("error must name the unknown key, got %s", rec.Body.String())
	}
	// A rejected request must not half-apply the keys that were spelled right.
	if s.config.Global.RateLimit.Window.String() != beforeWindow || s.config.Global.LogLevel == "warn" || s.config.Global.RateLimit.Requests != before {
		t.Errorf("a rejected PUT changed settings: %+v", s.config.Global.RateLimit)
	}

	// Control: the same request with the key spelled right is applied.
	putSettings(t, s, `{"global.rate_limit.requests": 5, "global.rate_limit.window": "30s", "global.log_level": "warn"}`)
	if s.config.Global.RateLimit.Requests != 5 || s.config.Global.LogLevel != "warn" {
		t.Errorf("control PUT not applied: %+v / %q", s.config.Global.RateLimit, s.config.Global.LogLevel)
	}
}
