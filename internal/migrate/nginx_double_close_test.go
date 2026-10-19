package migrate

// Regression: ParseNginx lost the ENTIRE pending location when one line
// closed both blocks ("proxy_pass http://backend; } }"). The end-of-server
// branch appended the config without flushing currentLoc, so the location —
// including directives parsed from earlier lines — was silently dropped, and
// a "deny all" path became silently public with no blocked_paths entry and no
// warning. F8602 (one-line location START), the location END line and the
// one-line/server-END fixes covered the sibling shapes; this pins the
// double-close flush.

import (
	"strings"
	"testing"
)

func TestNginxDoubleCloseLocationKept(t *testing.T) {
	src := "server {\n" +
		"server_name a.test;\n" +
		"root /var/www/a;\n" +
		"location /api/ {\n" +
		"proxy_pass http://127.0.0.1:9000; } }\n"

	configs, err := ParseNginx(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseNginx failed: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("got %d configs, want 1 (configs=%+v)", len(configs), configs)
	}
	if len(configs[0].Locations) != 1 {
		t.Fatalf("whole location lost when its closing brace shared the server's closing line (locations=%+v)", configs[0].Locations)
	}
	if got := configs[0].Locations[0].ProxyPass; got != "http://127.0.0.1:9000" {
		t.Fatalf("location's directive lost on the double-close line: ProxyPass=%q", got)
	}
}

func TestNginxDoubleCloseDenyAllStillBlocks(t *testing.T) {
	src := "server {\n" +
		"server_name a.test;\n" +
		"root /var/www/a;\n" +
		"location /private/ {\n" +
		"deny all; } }\n"

	configs, err := ParseNginx(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseNginx failed: %v", err)
	}
	if len(configs) != 1 || len(configs[0].Locations) != 1 {
		t.Fatalf("location lost on double-close (configs=%+v)", configs)
	}
	if !configs[0].Locations[0].DenyAll {
		t.Fatalf("'deny all; } }' dropped — path silently unprotected after migration")
	}
	domains := ConvertToUWAS(configs)
	if len(domains) != 1 {
		t.Fatalf("ConvertToUWAS returned %d domains", len(domains))
	}
	blocked := strings.Join(domains[0].Security.BlockedPaths, ",")
	if !strings.Contains(blocked, "/private/") {
		t.Fatalf("/private/ not in blocked_paths (got %q) — protection lost in migration", blocked)
	}
}

// TestNginxSiblingShapesUnchanged: the sibling shapes covered by F8602 and
// the earlier fixes keep working — a multi-line location, a location whose
// end-line directive precedes the server's own closing line, and a one-line
// server (round 4).
func TestNginxSiblingShapesUnchanged(t *testing.T) {
	src := "server { listen 80; return 301 https://$host$request_uri; }\n" +
		"server {\n" +
		"server_name a.test;\n" +
		"location /api/ {\n" +
		"proxy_pass http://127.0.0.1:9000; }\n" +
		"try_files $uri /index.html;\n" +
		"}\n"

	configs, err := ParseNginx(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseNginx failed: %v", err)
	}
	if len(configs) != 2 {
		t.Fatalf("got %d configs, want 2 (configs=%+v)", len(configs), configs)
	}
	if configs[0].Return == "" {
		t.Fatalf("one-line server's return lost: %+v", configs[0])
	}
	cfg := configs[1]
	if len(cfg.Locations) != 1 || cfg.Locations[0].ProxyPass != "http://127.0.0.1:9000" {
		t.Fatalf("location end-line shape changed: %+v", cfg)
	}
	if len(cfg.TryFiles) != 2 {
		t.Fatalf("server-level try_files lost: %+v", cfg)
	}
}
