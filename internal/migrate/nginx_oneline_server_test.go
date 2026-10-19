package migrate

// Regression: ParseNginx never closed a ONE-LINE server block. The
// server-start branch set braceDepth = 1 and continued without counting the
// line's own closing brace, so "server { listen 80; return 301
// https://$host$request_uri; }" — the canonical HTTP→HTTPS redirect
// one-liner from nginx guides — started a block that never ended: every
// following line merged into it, later servers were absorbed, and at EOF the
// incomplete config was dropped silently (zero configs, no error).
// F8602 fixed the same-line shape for one-line location blocks; this pins the
// server START line.

import (
	"strings"
	"testing"
)

func TestNginxOneLineServerThenMultilineServer(t *testing.T) {
	src := "server { listen 80; return 301 https://$host$request_uri; }\n" +
		"server {\n" +
		"server_name a.test;\n" +
		"root /var/www/a;\n" +
		"}\n"

	configs, err := ParseNginx(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseNginx failed: %v", err)
	}
	if len(configs) != 2 {
		t.Fatalf("got %d configs, want 2 — the one-line server block never closed (configs=%+v)", len(configs), configs)
	}
	if configs[0].Return == "" || !strings.HasPrefix(configs[0].Return, "301 https://") {
		t.Fatalf("one-line server's return directive lost: %+v", configs[0])
	}
	if len(configs[0].ListenPorts) != 1 || configs[0].ListenPorts[0] != "80" {
		t.Fatalf("one-line server's listen lost: %+v", configs[0])
	}
	if len(configs[1].ServerNames) != 1 || configs[1].ServerNames[0] != "a.test" {
		t.Fatalf("following server absorbed into the one-line block: %+v", configs)
	}
}

func TestNginxOneLineServerAlone(t *testing.T) {
	src := "server { server_name b.test; root /var/www/b; }\n"

	configs, err := ParseNginx(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseNginx failed: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("got %d configs, want 1 (configs=%+v)", len(configs), configs)
	}
	cfg := configs[0]
	if len(cfg.ServerNames) != 1 || cfg.ServerNames[0] != "b.test" || cfg.Root != "/var/www/b" {
		t.Fatalf("one-line server directives lost: %+v", cfg)
	}
}

// TestNginxOneLineServerRedirectConverts: the redirect one-liner converts to
// a UWAS redirect domain like its multi-line form.
func TestNginxOneLineServerRedirectConverts(t *testing.T) {
	src := "server { server_name c.test; return 301 https://c.test$request_uri; }\n"

	configs, err := ParseNginx(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseNginx failed: %v", err)
	}
	domains := ConvertToUWAS(configs)
	if len(domains) != 1 {
		t.Fatalf("got %d domains, want 1 (configs=%+v)", len(domains), configs)
	}
	d := domains[0]
	if d.Type != "redirect" || d.Redirect.Status != 301 || !d.Redirect.PreservePath {
		t.Fatalf("one-line redirect server mis-converted: %+v", d)
	}
}

// TestNginxMultiLineServerPairUnchanged: the standard shape keeps working.
func TestNginxMultiLineServerPairUnchanged(t *testing.T) {
	src := "server {\nserver_name x.test;\nroot /var/www/x;\n}\n" +
		"server {\nserver_name y.test;\nroot /var/www/y;\n}\n"

	configs, err := ParseNginx(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseNginx failed: %v", err)
	}
	if len(configs) != 2 ||
		configs[0].ServerNames[0] != "x.test" || configs[1].ServerNames[0] != "y.test" {
		t.Fatalf("standard two-server config mis-parsed: %+v", configs)
	}
}
