package migrate

// Regression: ParseNginx dropped a SERVER-level directive when it shared the
// line with the server block's closing brace ("try_files $uri /index.html; }",
// "return 301 https://r.test; }"). The end-of-server branch (braceDepth <= 0)
// appended the config and continued without parsing the line, so a site's
// SPA fallback or redirect was silently lost. F8602 fixed the same-line shape
// for one-line location STARTs and the round-3 fix covered the location END
// line; this pins the server-level closing line.

import (
	"strings"
	"testing"
)

func TestNginxServerEndLineDirectiveKept(t *testing.T) {
	src := "server {\n" +
		"server_name a.test;\n" +
		"root /var/www/a;\n" +
		"try_files $uri /index.html; }\n"

	configs, err := ParseNginx(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseNginx failed: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("got %d configs, want 1 (configs=%+v)", len(configs), configs)
	}
	if len(configs[0].TryFiles) != 2 {
		t.Fatalf("server's last directive dropped when it shares the closing-brace line: TryFiles=%v", configs[0].TryFiles)
	}
}

func TestNginxServerEndLineReturnConverts(t *testing.T) {
	src := "server {\n" +
		"server_name r.test;\n" +
		"return 301 https://r.test; }\n"

	configs, err := ParseNginx(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseNginx failed: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("got %d configs, want 1 (configs=%+v)", len(configs), configs)
	}
	if configs[0].Return == "" {
		t.Fatalf("server's return dropped when it shares the closing-brace line: %+v", configs[0])
	}
	domains := ConvertToUWAS(configs)
	if len(domains) != 1 {
		t.Fatalf("ConvertToUWAS returned %d domains", len(domains))
	}
	d := domains[0]
	if d.Type != "redirect" || d.Redirect.Status != 301 || !strings.HasPrefix(d.Redirect.Target, "https://r.test") {
		t.Fatalf("end-line return mis-converted: type=%q redirect=%+v", d.Type, d.Redirect)
	}
}

// TestNginxServerOwnLineBraceUnchanged: the unaffected multi-line shape and
// the location end-line shape (round 3) keep working.
func TestNginxServerOwnLineBraceUnchanged(t *testing.T) {
	src := "server {\n" +
		"server_name a.test;\n" +
		"location /api/ {\n" +
		"proxy_pass http://127.0.0.1:9000; }\n" +
		"try_files $uri /index.html;\n" +
		"}\n"

	configs, err := ParseNginx(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseNginx failed: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("got %d configs, want 1", len(configs))
	}
	cfg := configs[0]
	if len(cfg.Locations) != 1 || cfg.Locations[0].ProxyPass != "http://127.0.0.1:9000" {
		t.Fatalf("location end-line shape changed: %+v", cfg)
	}
	if len(cfg.TryFiles) != 2 {
		t.Fatalf("server-level try_files lost: %+v", cfg)
	}
}
