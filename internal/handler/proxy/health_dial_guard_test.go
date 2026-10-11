package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The health probe's dial is guarded by the same address policy as the proxy
// transport, so a hostname re-resolving to a blocked address between the URL
// check and the dial is refused (F4003).
func TestHealthClientDialRefusesBlockedAddress(t *testing.T) {
	for _, allowPrivate := range []bool{false, true} {
		hc := NewHealthChecker(NewUpstreamPool(nil), HealthConfig{Timeout: time.Second, AllowPrivate: allowPrivate}, newTestLogger())
		for _, target := range []string{"http://169.254.169.254/", "http://[fe80::1]/"} {
			_, err := hc.client.Get(target)
			if err == nil || !strings.Contains(err.Error(), "SSRF") {
				t.Errorf("allowPrivate=%v %s: err = %v, want SSRF refusal", allowPrivate, target, err)
			}
		}
	}
}

// Loopback upstreams (the common local-app case) are still probed.
func TestHealthClientStillProbesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	hc := NewHealthChecker(NewUpstreamPool(nil), HealthConfig{Timeout: time.Second}, newTestLogger())
	resp, err := hc.client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}
