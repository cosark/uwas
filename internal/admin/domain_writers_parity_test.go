package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/uwaserver/uwas/internal/auth"
	"github.com/uwaserver/uwas/internal/config"
)

// The same domain configuration is written through several admin entry
// points: Add and Update (JSON), the raw YAML editor, the bulk import and the
// unknown-host alias. Every guard the API grew was added to some of them, and
// the writers drifted apart (F12000, F12200, F12201, F12800, F12801, F13100).
// This differential test drives the same mutation through each writer as a
// reseller and as an admin and checks two properties that must hold whichever
// door is used:
//
//   - a field a reseller may not set is not stored by any writer, and
//   - any write a writer accepts leaves a configuration the next start
//     accepts (config.ValidateWithDefaults), because a saved config the loader
//     rejects keeps the server from starting.

type parityEnv struct {
	t       *testing.T
	s       *Server
	webRoot string
	base    []byte // yaml of the starting domains
}

const (
	parityReseller = "reseller"
	parityAdmin    = "admin"
)

func newParityEnv(t *testing.T) *parityEnv {
	t.Helper()
	dir := t.TempDir()
	webRoot := filepath.Join(dir, "www")
	mk := func(host string, aliases ...string) config.Domain {
		root := filepath.Join(webRoot, host, "public_html")
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatal(err)
		}
		return config.Domain{Host: host, Type: "static", Root: root, Aliases: aliases, SSL: config.SSLConfig{Mode: "off"}}
	}
	domains := []config.Domain{
		mk("mine.com"),
		mk("victim.com", "shop.victim.com"),
		mk("bücher.example"),
	}
	s := testServerFromConfig(t, &config.Config{
		Global:  config.GlobalConfig{WebRoot: webRoot, LogLevel: "error", LogFormat: "text"},
		Domains: domains,
	})
	mgr, err := auth.NewManager(t.TempDir(), "adminkey-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	s.authMgr = mgr // the real manager: CanManageDomain compares hosts canonically
	s.configPath = filepath.Join(dir, "uwas.yaml")
	if err := s.persistConfig(); err != nil {
		t.Fatal(err)
	}
	base, err := yaml.Marshal(domains)
	if err != nil {
		t.Fatal(err)
	}
	return &parityEnv{t: t, s: s, webRoot: webRoot, base: base}
}

func (e *parityEnv) reset() {
	e.t.Helper()
	var domains []config.Domain
	if err := yaml.Unmarshal(e.base, &domains); err != nil {
		e.t.Fatal(err)
	}
	e.s.configMu.Lock()
	e.s.config.Domains = domains
	e.s.configMu.Unlock()
	if p, err := e.s.domainFilePath("mine.com"); err == nil {
		_ = os.RemoveAll(filepath.Dir(p))
	}
}

func (e *parityEnv) user(role string) *auth.User {
	if role == parityAdmin {
		return &auth.User{ID: "a", Username: "a", Role: auth.RoleAdmin, Enabled: true}
	}
	return &auth.User{ID: "r", Username: "r", Role: auth.RoleReseller, Enabled: true, Domains: []string{"mine.com", "newmine.com"}}
}

func (e *parityEnv) call(role, method, path, body string) (int, string) {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r = r.WithContext(auth.WithUser(r.Context(), e.user(role)))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.s.mux.ServeHTTP(rec, r)
	return rec.Code, rec.Body.String()
}

func (e *parityEnv) domains() []config.Domain {
	e.s.configMu.RLock()
	defer e.s.configMu.RUnlock()
	return append([]config.Domain(nil), e.s.config.Domains...)
}

// loads reports whether the configuration the next start would read is valid.
func (e *parityEnv) loads(domains []config.Domain) error {
	cfg := config.Config{
		Global:  config.GlobalConfig{LogLevel: "info", LogFormat: "json", Admin: config.AdminConfig{Listen: "127.0.0.1:9443"}, WebRoot: e.webRoot},
		Domains: domains,
	}
	return config.ValidateWithDefaults(&cfg)
}

// writeResult is what a writer left behind.
type writeResult struct {
	status int
	body   string
	stored *config.Domain  // the domain the request was about, as stored; nil when it was refused
	all    []config.Domain // the domain list the next start would read
}

type writer struct {
	name string
	run  func(e *parityEnv, role string, frag map[string]any) writeResult
}

func mergeFrag(base, frag map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range frag {
		out[k] = v
	}
	return out
}

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var parityWriters = []writer{
	{"add", func(e *parityEnv, role string, frag map[string]any) writeResult {
		body := mustMarshal(e.t, mergeFrag(map[string]any{"host": "newmine.com", "type": "static", "ssl": map[string]any{"mode": "off"}}, frag))
		code, resp := e.call(role, http.MethodPost, "/api/v1/domains", body)
		res := writeResult{status: code, body: resp}
		if code < 300 {
			res.all = e.domains()
			for _, d := range res.all {
				if strings.EqualFold(d.Host, fmt.Sprint(mergeFrag(map[string]any{"host": "newmine.com"}, frag)["host"])) || d.Host == "newmine.com" {
					dd := d
					res.stored = &dd
				}
			}
		}
		return res
	}},
	{"update", func(e *parityEnv, role string, frag map[string]any) writeResult {
		code, resp := e.call(role, http.MethodPut, "/api/v1/domains/mine.com", mustMarshal(e.t, frag))
		res := writeResult{status: code, body: resp}
		if code < 300 {
			res.all = e.domains()
			host := "mine.com"
			if h, ok := frag["host"].(string); ok {
				host = h
			}
			for _, d := range res.all {
				if strings.EqualFold(d.Host, host) || d.Host == "mine.com" {
					dd := d
					res.stored = &dd
				}
			}
		}
		return res
	}},
	{"rawput", func(e *parityEnv, role string, frag map[string]any) writeResult {
		var cur config.Domain
		for _, d := range e.domains() {
			if d.Host == "mine.com" {
				cur = d
			}
		}
		next := cur
		// json.Unmarshal merges into the existing value, the same patch the
		// JSON writers apply, so one fragment drives all of them.
		if err := json.Unmarshal([]byte(mustMarshal(e.t, frag)), &next); err != nil {
			return writeResult{status: -1, body: "fragment not representable: " + err.Error()}
		}
		y, err := yaml.Marshal(next)
		if err != nil {
			return writeResult{status: -1, body: err.Error()}
		}
		code, resp := e.call(role, http.MethodPut, "/api/v1/config/domains/mine.com/raw", mustMarshal(e.t, map[string]string{"content": string(y)}))
		res := writeResult{status: code, body: resp}
		if code < 300 {
			p, _ := e.s.domainFilePath("mine.com")
			data, err := os.ReadFile(p)
			if err != nil {
				e.t.Fatalf("rawput accepted but wrote nothing: %v", err)
			}
			var got config.Domain
			if err := yaml.Unmarshal(data, &got); err != nil {
				e.t.Fatal(err)
			}
			res.stored = &got
			for _, d := range e.domains() {
				if d.Host == "mine.com" {
					res.all = append(res.all, got)
				} else {
					res.all = append(res.all, d)
				}
			}
		}
		return res
	}},
}

type parityMutation struct {
	name string
	frag map[string]any
	// forbidden reports whether the stored domain carries what a reseller may
	// not set; nil when a reseller may set the field.
	forbidden func(d config.Domain) bool
}

func (e *parityEnv) mutations() []parityMutation {
	sib := filepath.Join(e.webRoot, "victim.com", "public_html")
	up := map[string]any{"upstreams": []any{map[string]any{"address": "http://127.0.0.1:1"}}}
	many := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = fmt.Sprintf("f%d.html", i)
		}
		return out
	}
	return []parityMutation{
		{"root of a sibling tenant", map[string]any{"root": sib}, func(d config.Domain) bool { return d.Root == sib }},
		{"root outside web_root", map[string]any{"root": "/etc"}, func(d config.Domain) bool { return d.Root == "/etc" }},
		{"type proxy", map[string]any{"type": "proxy", "proxy": up}, func(d config.Domain) bool { return d.Type == "proxy" }},
		{"proxy on a static domain", map[string]any{"proxy": up}, func(d config.Domain) bool { return len(d.Proxy.Upstreams) > 0 }},
		{"location root", map[string]any{"locations": []any{map[string]any{"match": "/x/", "root": "/etc"}}}, func(d config.Domain) bool {
			for _, l := range d.Locations {
				if l.Root == "/etc" {
					return true
				}
			}
			return false
		}},
		{"location proxy_pass", map[string]any{"locations": []any{map[string]any{"match": "/api/", "proxy_pass": "http://169.254.169.254/"}}}, func(d config.Domain) bool {
			for _, l := range d.Locations {
				if l.ProxyPass != "" {
					return true
				}
			}
			return false
		}},
		{"error page path", map[string]any{"error_pages": map[string]any{"404": "../../../etc/passwd"}}, func(d config.Domain) bool { return len(d.ErrorPages) > 0 }},
		{"php.fpm_address", map[string]any{"php": map[string]any{"fpm_address": "unix:/run/php/other.sock"}}, func(d config.Domain) bool { return d.PHP.FPMAddress != "" }},
		{"ssl cert and key paths", map[string]any{"ssl": map[string]any{"mode": "manual", "cert": "/etc/ssl/private/a.pem", "key": "/etc/ssl/private/a.key"}}, func(d config.Domain) bool { return d.SSL.Cert != "" || d.SSL.Key != "" }},
		{"ssl client_ca", map[string]any{"ssl": map[string]any{"mode": "off", "client_auth": "request", "client_ca": "/etc/ssl/ca.pem"}}, func(d config.Domain) bool { return d.SSL.ClientCA != "" }},
		{"internal_aliases", map[string]any{"internal_aliases": []any{"/etc/"}}, func(d config.Domain) bool { return len(d.InternalAliases) > 0 }},
		{"access_log path", map[string]any{"access_log": map[string]any{"path": "/etc/cron.d/x"}}, func(d config.Domain) bool { return d.AccessLog.Path != "" }},
		{"webhook_secret", map[string]any{"webhook_secret": "chosen"}, func(d config.Domain) bool { return d.WebhookSecret != "" }},
		{"dedicated ip", map[string]any{"ip": "203.0.113.5"}, func(d config.Domain) bool { return d.IP != "" }},
		{"redirect target", map[string]any{"redirect": map[string]any{"target": "https://evil.example"}}, func(d config.Domain) bool { return d.Redirect.Target != "" }},
		{"app command", map[string]any{"app": map[string]any{"command": "/bin/sh"}}, func(d config.Domain) bool { return d.App.Command != "" }},
		{"php.env PHP_ADMIN_VALUE", map[string]any{"php": map[string]any{"env": map[string]any{"PHP_ADMIN_VALUE": "open_basedir=/"}}}, func(d config.Domain) bool { _, ok := d.PHP.Env["PHP_ADMIN_VALUE"]; return ok }},
		{"alias nobody assigned", map[string]any{"aliases": []any{"unrelated.example"}}, func(d config.Domain) bool { return containsHost(d.Aliases, "unrelated.example") }},
		{"alias that is another host", map[string]any{"aliases": []any{"victim.com"}}, func(d config.Domain) bool { return containsHost(d.Aliases, "victim.com") }},
		{"alias another domain owns as alias", map[string]any{"aliases": []any{"shop.victim.com"}}, func(d config.Domain) bool { return containsHost(d.Aliases, "shop.victim.com") }},
		{"alias that is an IDN twin", map[string]any{"aliases": []any{"xn--bcher-kva.example"}}, func(d config.Domain) bool { return containsHost(d.Aliases, "xn--bcher-kva.example") }},

		// Not a privilege question: these are invalid for everyone.
		{"negative cpu limit", map[string]any{"resources": map[string]any{"cpu_percent": -5}}, nil},
		{"negative bandwidth limit", map[string]any{"bandwidth": map[string]any{"enabled": true, "monthly_limit": -5, "action": "block"}}, nil},
		{"misspelt bandwidth action", map[string]any{"bandwidth": map[string]any{"enabled": true, "monthly_limit": 1048576, "action": "Block"}}, nil},
		{"client_auth spelling", map[string]any{"ssl": map[string]any{"mode": "off", "client_auth": "required", "client_ca": ""}}, nil},
		{"client_auth without a CA", map[string]any{"ssl": map[string]any{"mode": "off", "client_auth": "require"}}, nil},
		{"unknown waf rule", map[string]any{"security": map[string]any{"waf": map[string]any{"enabled": true, "rules": []any{"xxs"}}}}, nil},
		{"geo country name", map[string]any{"security": map[string]any{"geo_block_countries": []any{"Turkey"}}}, nil},
		{"ip_blacklist entry", map[string]any{"security": map[string]any{"ip_blacklist": []any{"not an ip"}}}, nil},
		{"rewrite flag", map[string]any{"rewrites": []any{map[string]any{"match": "^/a", "to": "/b", "flags": []any{"Forbidden"}}}}, nil},
		{"maintenance allowed_ips", map[string]any{"maintenance": map[string]any{"enabled": true, "allowed_ips": []any{"office"}}}, nil},
		{"65 try_files", map[string]any{"try_files": many(65)}, nil},
		{"65 index_files", map[string]any{"index_files": many(65)}, nil},
		{"huge location regex", map[string]any{"locations": []any{map[string]any{"match": "~(a{1000}){1000}", "cache_control": "no-store"}}}, nil},
		{"alias with a space", map[string]any{"aliases": []any{"bad alias"}}, nil},
		{"alias equal to the host", map[string]any{"aliases": []any{"mine.com"}}, nil},
		{"negative cache ttl", map[string]any{"cache": map[string]any{"enabled": true, "ttl": -1}}, nil},
		{"unknown ssl mode", map[string]any{"ssl": map[string]any{"mode": "Auto-ish"}}, nil},
		{"unknown canonical_host", map[string]any{"canonical_host": "sub"}, nil},
	}
}

func containsHost(list []string, host string) bool {
	for _, h := range list {
		if strings.EqualFold(h, host) {
			return true
		}
	}
	return false
}

func statusClass(code int) string {
	switch {
	case code < 0:
		return "n/a"
	case code < 300:
		return "ACCEPT"
	}
	return fmt.Sprintf("%d", code)
}

// TestDomainWritersParityMatrix prints, for every mutation, what each writer
// did for a reseller and an admin. It asserts the two properties above.
func TestDomainWritersParity(t *testing.T) {
	e := newParityEnv(t)
	for _, m := range e.mutations() {
		for _, role := range []string{parityReseller, parityAdmin} {
			row := []string{}
			for _, w := range parityWriters {
				e.reset()
				res := w.run(e, role, m.frag)
				row = append(row, fmt.Sprintf("%s=%s", w.name, statusClass(res.status)))
				if res.status < 0 || res.status >= 300 {
					continue
				}
				if role == parityReseller && m.forbidden != nil && res.stored != nil && m.forbidden(*res.stored) {
					t.Errorf("%s: %s as a reseller stored a field a reseller may not set (status %d)", m.name, w.name, res.status)
				}
				if err := e.loads(res.all); err != nil {
					t.Errorf("%s: %s as %s accepted a write the next start refuses to load: %v", m.name, w.name, role, err)
				}
			}
			t.Logf("%-38s %-8s %s", m.name, role, strings.Join(row, "  "))
		}
	}
}

// hostWriters are the writers that take a hostname as the thing being
// written. The bulk import and the unknown-host alias have no other field to
// mutate, so they join the table here.
var hostWriters = []writer{
	{"add", func(e *parityEnv, role string, frag map[string]any) writeResult {
		return parityWriters[0].run(e, role, frag)
	}},
	{"rename", func(e *parityEnv, role string, frag map[string]any) writeResult {
		return parityWriters[1].run(e, role, frag)
	}},
	{"rawput", func(e *parityEnv, role string, frag map[string]any) writeResult {
		return parityWriters[2].run(e, role, frag)
	}},
	{"import", func(e *parityEnv, role string, frag map[string]any) writeResult {
		host, _ := frag["host"].(string)
		code, resp := e.call(role, http.MethodPost, "/api/v1/domains/import",
			mustMarshal(e.t, map[string]any{"domains": []any{map[string]any{"host": host, "ssl": "off"}}}))
		res := writeResult{status: code, body: resp}
		if code < 300 {
			var out struct {
				Added []string `json:"added"`
			}
			_ = json.Unmarshal([]byte(resp), &out)
			if len(out.Added) == 0 {
				res.status = 422 // answered 200 but added nothing: a refusal
				return res
			}
			res.all = e.domains()
		}
		return res
	}},
	{"unknown-alias", func(e *parityEnv, role string, frag map[string]any) writeResult {
		host, _ := frag["host"].(string)
		code, resp := e.call(role, http.MethodPost, "/api/v1/unknown-domains/"+url.PathEscape(host)+"/alias",
			mustMarshal(e.t, map[string]any{"domain": "mine.com"}))
		res := writeResult{status: code, body: resp}
		if code < 300 {
			var out struct {
				Status string `json:"status"`
			}
			_ = json.Unmarshal([]byte(resp), &out)
			if out.Status != "redirect" {
				res.status = 422
				return res
			}
			res.all = e.domains()
		}
		return res
	}},
}

func TestDomainHostWritersParity(t *testing.T) {
	e := newParityEnv(t)
	hosts := []string{
		"fresh.example", // control: a new valid host
		"bad host!",     // not a hostname
		"-bad.example",  // leading hyphen
		"a..b.example",  // empty label
		"under_score.example",
		"*.wild.example",
		"xn--bcher-kva.example", // IDN twin of an existing Unicode host
		"BÜCHER.example",        // case twin
		"shop.victim.com",       // an alias another domain owns
		"VICTIM.com",            // case twin of a host
		"victim.com.",           // trailing dot twin
		"www.victim.com",        // www twin
	}
	for _, host := range hosts {
		row := []string{}
		for _, w := range hostWriters {
			e.reset()
			res := w.run(e, parityAdmin, map[string]any{"host": host})
			row = append(row, fmt.Sprintf("%s=%s", w.name, statusClass(res.status)))
			if res.status < 0 || res.status >= 300 {
				continue
			}
			if err := e.loads(res.all); err != nil {
				t.Errorf("host %q: %s accepted a write the next start refuses to load: %v", host, w.name, err)
			}
		}
		t.Logf("%-26q %s", host, strings.Join(row, "  "))
	}
}

// TestUpdateOfAnExistingNonStandardHostIsNotRefused: Update checked the host
// against IsValidHostname even when the request did not change it, so a
// domain whose host the loader accepts (an internationalised name, or one with
// an underscore, written in YAML) could not be edited through the API at all:
// every PUT answered "invalid hostname".
func TestUpdateOfAnExistingNonStandardHostIsNotRefused(t *testing.T) {
	e := newParityEnv(t)
	for _, host := range []string{"bücher.example", "my_app.example"} {
		e.reset()
		if host != "bücher.example" {
			e.s.configMu.Lock()
			root := filepath.Join(e.webRoot, host, "public_html")
			_ = os.MkdirAll(root, 0o755)
			e.s.config.Domains = append(e.s.config.Domains, config.Domain{Host: host, Type: "static", Root: root, SSL: config.SSLConfig{Mode: "off"}})
			e.s.configMu.Unlock()
		}
		code, body := e.call(parityAdmin, http.MethodPut, "/api/v1/domains/"+url.PathEscape(host), `{"cache":{"enabled":true,"ttl":60}}`)
		if code != http.StatusOK {
			t.Errorf("PUT of %q (host unchanged) = %d %s, want 200", host, code, strings.TrimSpace(body))
		}
	}
}
