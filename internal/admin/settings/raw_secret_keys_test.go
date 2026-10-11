package settings

import (
	"strings"
	"testing"
)

// F9500: credential keys read by the DNS providers (token), the S3 backup
// (access_key) and the per-domain deploy webhook (webhook_secret) are masked in
// the raw editor and restored from disk on save, like the other secrets.
func TestRawSecretKeysMaskAndRestore(t *testing.T) {
	old := "dns_credentials:\n  token: realtoken\n  access_key: realak\nwebhook_secret: realhook\n"
	masked := old
	for _, key := range rawSecretKeys {
		masked = maskYAMLValue(masked, key)
	}
	for _, v := range []string{"realtoken", "realak", "realhook"} {
		if strings.Contains(masked, v) {
			t.Fatalf("%s survived masking:\n%s", v, masked)
		}
	}
	restored := masked
	for _, key := range rawSecretKeys {
		restored = unmaskYAMLValue(restored, old, key)
	}
	for _, v := range []string{"token: realtoken", "access_key: realak", "webhook_secret: realhook"} {
		if !strings.Contains(restored, v) {
			t.Errorf("%q not restored:\n%s", v, restored)
		}
	}
	if strings.Contains(restored, "********") {
		t.Errorf("mask reached disk:\n%s", restored)
	}
}
