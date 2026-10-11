package admin

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F9500: the raw config editor masks secrets by a fixed key list that lacks
// keys the code really uses for credentials: dns_credentials.token (Cloudflare
// fallback key), access_key (Route53 / S3, which SettingsGet already masks) and
// the per-domain webhook_secret.
func TestConfigRawGetMasksDNSTokenAccessKeyWebhookSecret(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "uwas.yaml")
	cfg := "global:\n  acme:\n    dns_credentials:\n      token: \"SECRET-DNS-TOKEN\"\n      access_key: \"SECRET-ACCESS-KEY\"\n" +
		"domains:\n  - host: a.test\n    webhook_secret: \"SECRET-WEBHOOK\"\n  api_token: \"CONTROL-api-token\"\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	s := testServer()
	s.SetConfigPath(cfgPath)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/config/raw", nil))
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	got := resp["content"]
	if strings.Contains(got, "CONTROL-api-token") {
		t.Fatalf("control failed: api_token leaked, proof invalid")
	}
	leaked := 0
	for _, v := range []string{"SECRET-DNS-TOKEN", "SECRET-ACCESS-KEY", "SECRET-WEBHOOK"} {
		if strings.Contains(got, v) {
			leaked++
			t.Logf("ACTUAL: raw config still shows %s", v)
		}
	}
	t.Logf("EXPECTED: all 3 masked, ACTUAL leaked=%d", leaked)
	if leaked > 0 {
		t.Fail()
		return
	}
}
