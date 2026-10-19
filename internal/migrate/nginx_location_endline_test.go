package migrate

// Regression: ParseNginx dropped a location's last directive when it shared
// the line with the block's closing brace ("proxy_pass http://backend; }",
// "deny all; }"). The location-end branch closed the block and continued
// without parsing the line, so the directive was silently lost: a migrated
// site lost its proxy backend and was mis-typed static, and a path protected
// by "deny all" became silently public with no blocked_paths entry and no
// warning. F8602 fixed the same-line shape for the block's START; this pins
// the END line.

import (
	"strings"
	"testing"
)

func TestNginxLocationEndLineDirectiveKept(t *testing.T) {
	src := "server {\n" +
		"server_name a.test;\n" +
		"root /var/www/a;\n" +
		"location /api/ {\n" +
		"proxy_pass http://127.0.0.1:9000; }\n" +
		"}\n"

	configs, err := ParseNginx(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseNginx failed: %v", err)
	}
	if len(configs) != 1 || len(configs[0].Locations) != 1 {
		t.Fatalf("unexpected parse: %+v", configs)
	}
	if got := configs[0].Locations[0].ProxyPass; got != "http://127.0.0.1:9000" {
		t.Fatalf("location's last directive dropped when it shares the closing-brace line: ProxyPass=%q", got)
	}
}

func TestNginxLocationEndLineDenyAllStillBlocks(t *testing.T) {
	src := "server {\n" +
		"server_name a.test;\n" +
		"root /var/www/a;\n" +
		"location /private/ {\n" +
		"deny all; }\n" +
		"}\n"

	configs, err := ParseNginx(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseNginx failed: %v", err)
	}
	if len(configs) != 1 || len(configs[0].Locations) != 1 {
		t.Fatalf("unexpected parse: %+v", configs)
	}
	if !configs[0].Locations[0].DenyAll {
		t.Fatalf("'deny all; }' dropped — path silently unprotected after migration")
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

// TestNginxLocationEndLineMultipleDirectives: every directive on the closing
// line is recorded, not just the first.
func TestNginxLocationEndLineMultipleDirectives(t *testing.T) {
	src := "server {\n" +
		"server_name a.test;\n" +
		"location /app/ {\n" +
		"proxy_pass http://127.0.0.1:7000; try_files $uri /index.html; }\n" +
		"}\n"

	configs, err := ParseNginx(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseNginx failed: %v", err)
	}
	if len(configs) != 1 || len(configs[0].Locations) != 1 {
		t.Fatalf("unexpected parse: %+v", configs)
	}
	loc := configs[0].Locations[0]
	if loc.ProxyPass != "http://127.0.0.1:7000" {
		t.Fatalf("ProxyPass=%q, want http://127.0.0.1:7000", loc.ProxyPass)
	}
	if len(loc.TryFiles) == 0 || loc.TryFiles[0] != "$uri" {
		t.Fatalf("TryFiles=%v, want [$uri /index.html]", loc.TryFiles)
	}
}

// TestNginxLocationOwnLineBraceUnchanged: the unaffected multi-line shape and
// the F8602 one-line start keep working.
func TestNginxLocationOwnLineBraceUnchanged(t *testing.T) {
	src := "server {\n" +
		"server_name a.test;\n" +
		"location = /favicon.ico { access_log off; }\n" +
		"root /var/www/a;\n" +
		"location /api/ {\n" +
		"proxy_pass http://127.0.0.1:9000;\n" +
		"}\n" +
		"}\n"

	configs, err := ParseNginx(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseNginx failed: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("server count %d, want 1", len(configs))
	}
	cfg := configs[0]
	if len(cfg.Locations) != 2 {
		t.Fatalf("locations %d, want 2 (F8602 regression?): %+v", len(cfg.Locations), cfg)
	}
	if cfg.Root != "/var/www/a" || cfg.Locations[1].ProxyPass != "http://127.0.0.1:9000" {
		t.Fatalf("directives after one-line location swallowed: %+v", cfg)
	}
}
