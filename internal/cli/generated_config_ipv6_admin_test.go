package cli

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

// The interactive first-run setup accepts any "Admin bind address". An IPv6
// literal must come out as a host:port the listener can parse: "::1" + ":9443"
// glued into "::1:9443" is "too many colons" to net.Listen, so the generated
// config would start with an admin API that can never bind.
func TestGeneratedConfigAdminListenIPv6(t *testing.T) {
	base := t.TempDir()
	cases := []struct {
		name, bind, wantHost string
		control              bool
	}{
		{"ipv4 control", "127.0.0.1", "127.0.0.1", true},
		{"bracketed ipv6 control", "[::1]", "::1", true},
		{"bare ipv6 loopback", "::1", "::1", false},
		{"bare ipv6 any", "::", "::", false},
		{"bare ipv6 global", "2001:db8::5", "2001:db8::5", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := generateDefaultConfig("8080", "9443", tc.bind, "k-0123456789abcdef", "123456",
				filepath.Join(base, "uwas"), filepath.Join(base, "www"), "")
			p := filepath.Join(t.TempDir(), "uwas.yaml")
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(p)
			if err != nil {
				t.Fatalf("EXPECTED: generated config for admin bind %q loads\nACTUAL: %v\nPROBLEM CONFIRMED", tc.bind, err)
			}
			listen := cfg.Global.Admin.Listen
			host, port, err := net.SplitHostPort(listen)
			if err != nil || host != tc.wantHost || port != "9443" {
				t.Fatalf("EXPECTED: admin.listen splits into host %q port 9443\nACTUAL: admin.listen = %q (split err: %v)\nPROBLEM CONFIRMED", tc.wantHost, listen, err)
			}
			if strings.Count(listen, ":") > 1 && !strings.HasPrefix(listen, "[") {
				t.Fatalf("EXPECTED: bracketed IPv6 listen\nACTUAL: %q\nPROBLEM CONFIRMED", listen)
			}
		})
	}
}
