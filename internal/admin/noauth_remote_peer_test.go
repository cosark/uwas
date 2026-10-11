package admin

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
	"github.com/uwaserver/uwas/internal/metrics"
	"github.com/uwaserver/uwas/internal/middleware"
)

func peerDo(h http.Handler, remote, method, path, body string, hdr map[string]string) (int, string) {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = remote
	r.Host = "127.0.0.1:9443"
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code, rec.Body.String()
}

// F16101: an admin API without credentials is meant to be loopback-only. Start
// refuses to bind it anywhere else, but the credentials can be removed while it
// runs (a settings PUT with an emptied api_key field, or a config edit and
// reload) and the listener stays where it is. The middleware then granted the
// virtual admin to anything that sent a loopback Host header, which a remote
// client chooses freely.
func TestClearingTheAPIKeyDoesNotOpenTheAdminAPIToRemoteClients(t *testing.T) {
	const key = "strong-unique-key-1"
	cfg := &config.Config{Global: config.GlobalConfig{Admin: config.AdminConfig{Listen: "0.0.0.0:9443", APIKey: key}}}
	s := New(cfg, logger.New("error", "text"), metrics.New())
	s.configPath = filepath.Join(t.TempDir(), "uwas.yaml")
	h := middleware.RequestID()(s.authMiddleware(requireJSONMiddleware(s.mux)))

	const remote, local = "203.0.113.9:40000", "127.0.0.1:40000"
	if code, _ := peerDo(h, remote, "GET", "/api/v1/config/raw", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("control: remote client without the key = %d, want 401", code)
	}
	// PUT /settings now refuses to clear the only credential of a public admin
	// API (F16400), but the state is still reachable without that check: a
	// config file edited by hand and loaded by a reload applies the key the
	// same way. The peer rule below is what keeps that state safe, so the test
	// reaches it directly.
	if code, _ := peerDo(h, "10.0.0.5:1", "PUT", "/api/v1/settings", `{"global.admin.api_key": ""}`, map[string]string{
		"Authorization": "Bearer " + key, "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest",
	}); code != http.StatusBadRequest {
		t.Fatalf("clearing the key of a public admin API = %d, want 400 (F16400)", code)
	}
	s.configMu.Lock()
	s.config.Global.Admin.APIKey = ""
	s.configMu.Unlock()

	// The first-run mode itself keeps working for the machine's own clients.
	for _, peer := range []string{local, "[::1]:40000", "[::ffff:127.0.0.1]:40000"} {
		if code, _ := peerDo(h, peer, "GET", "/api/v1/stats", "", nil); code != http.StatusOK {
			t.Errorf("loopback peer %s = %d, want 200", peer, code)
		}
	}

	if code, body := peerDo(h, remote, "GET", "/api/v1/config/raw", "", nil); code == http.StatusOK {
		t.Errorf("a remote client got the admin API with no credentials (%d, %d bytes of config)", code, len(body))
	}
	if code, _ := peerDo(h, remote, "PUT", "/api/v1/settings", `{"global.admin.api_key": "attacker"}`, map[string]string{
		"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest",
	}); code == http.StatusOK {
		t.Error("a remote client could write settings with no credentials")
	}
}
