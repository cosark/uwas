package proxy

import (
	"strings"
	"testing"
)

// F7505: the raw WebSocket tunnel must launder hop-by-hop headers like the HTTP
// path: the client's Connection header (and the fields it names) is replaced by
// the handshake's own "Connection: Upgrade", and Proxy-Authorization, Keep-Alive
// and Te are not forwarded.
func TestWebSocketTunnelLaundersHopByHopHeaders(t *testing.T) {
	raw := tunnelBackendCapture(t, map[string]string{
		"Connection":            "Upgrade, X-Forwarded-For, X-Real-IP",
		"Proxy-Authorization":   "Basic Y2xpZW50OnNlY3JldA==",
		"Keep-Alive":            "timeout=99",
		"Te":                    "trailers",
		"Sec-WebSocket-Key":     "dGhlIHNhbXBsZSBub25jZQ==",
		"Sec-WebSocket-Version": "13",
	})

	// Control: the tunnel ran, and the handshake headers survive.
	if got := tunnelHeaderValues(raw, "X-Forwarded-For"); len(got) == 0 || got[0] != "1.2.3.4" {
		t.Fatalf("control: tunnel did not run, backend saw %q", raw)
	}
	if got := tunnelHeaderValues(raw, "Upgrade"); len(got) != 1 || !strings.EqualFold(got[0], "websocket") {
		t.Errorf("Upgrade = %v, want [websocket]", got)
	}
	if got := tunnelHeaderValues(raw, "Sec-WebSocket-Key"); len(got) != 1 {
		t.Errorf("Sec-WebSocket-Key = %v, want it forwarded", got)
	}

	if got := strings.Join(tunnelHeaderValues(raw, "Connection"), ","); got != "Upgrade" {
		t.Errorf("Connection = %q, want exactly \"Upgrade\"", got)
	}
	for _, name := range []string{"Proxy-Authorization", "Keep-Alive", "Te"} {
		if got := tunnelHeaderValues(raw, name); len(got) != 0 {
			t.Errorf("%s = %v, want it not forwarded", name, got)
		}
	}
}
