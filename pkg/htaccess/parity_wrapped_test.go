package htaccess

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"testing"
)

// Every consumer of a parsed .htaccess must read the same directive the same
// way whether it stands alone or sits inside a conditional section that is
// certainly active. The sections below are all active; a difference between a
// bare directive and its wrapped twin means one consumer treats conditional
// sections differently from the others (R125).

var activeWrappers = []struct{ name, open, close string }{
	{"IfModule loaded", "<IfModule mod_rewrite.c>", "</IfModule>"},
	{"IfModule _module spelling", "<IfModule rewrite_module>", "</IfModule>"},
	{"IfModule negated unknown", "<IfModule !mod_no_such_module_zz.c>", "</IfModule>"},
	{"IfDefine negated", "<IfDefine !UWAS_NO_SUCH_DEFINE>", "</IfDefine>"},
	{"IfVersion holds", "<IfVersion >= 2.2>", "</IfVersion>"},
	{"upper-case section", "<IFMODULE mod_rewrite.c>", "</IFMODULE>"},
	{"nested", "<IfDefine !UWAS_NO_SUCH_DEFINE>\n<IfModule mod_rewrite.c>", "</IfModule>\n</IfDefine>"},
}

var parityCorpus = []struct{ name, rules string }{
	{"require all denied", "Require all denied"},
	{"require ip allow", "Require ip 203.0.113.0/24"},
	{"order allow deny", "Order Allow,Deny\nAllow from 203.0.113.0/24\nDeny from all"},
	{"deny from env", "SetEnvIf User-Agent \"Bad\" bad\nOrder Allow,Deny\nAllow from all\nDeny from env=bad"},
	{"limit post denied", "<Limit POST>\nRequire all denied\n</Limit>"},
	{"limitexcept get denied", "<LimitExcept GET>\nRequire all denied\n</LimitExcept>"},
	{"requireall mixed", "<RequireAll>\nRequire ip 203.0.113.0/24\nRequire valid-user\n</RequireAll>"},
	{"auth basic", "AuthType Basic\nAuthName \"P\"\nAuthUserFile .htpasswd\nRequire valid-user"},
	{"auth abs file", "AuthType Basic\nAuthUserFile /srv/pw\nRequire valid-user"},
	{"header set", "Header set X-Frame-Options DENY"},
	{"header always env", "Header always set Strict-Transport-Security \"max-age=1\" env=HTTPS"},
	{"expires", "ExpiresActive On\nExpiresByType text/css \"access plus 1 hour\"\nExpiresDefault \"access plus 1 day\""},
	{"expires off", "ExpiresActive Off"},
	{"addtype", "AddType image/svg+xml .vec"},
	{"directoryindex", "DirectoryIndex start.html"},
	{"errordocument path", "ErrorDocument 404 /e404.html"},
	{"errordocument text", "ErrorDocument 403 \"no entry\""},
	{"options minus indexes", "Options -Indexes"},
	{"options none", "Options None"},
	{"php engine off", "php_flag engine off"},
	{"removehandler", "RemoveHandler .php"},
	{"sethandler none", "SetHandler none"},
	{"php value", "php_value memory_limit 64M\nphp_flag display_errors off"},
	{"rewrite", "RewriteEngine On\nRewriteRule ^x$ /y [L]"},
	{"redirect", "Redirect 301 /old /new"},
	{"filesmatch deny", "<FilesMatch \"\\.php$\">\nRequire all denied\n</FilesMatch>"},
	{"files deny", "<Files wp-config.php>\nRequire all denied\n</Files>"},
	{"files tilde deny", "<Files ~ \"^\\.ht\">\nRequire all denied\n</Files>"},
	{"filesmatch header", "<FilesMatch \"\\.js$\">\nHeader set X-A 1\n</FilesMatch>"},
	{"filesmatch ip allow", "<FilesMatch \"\\.php$\">\nRequire ip 203.0.113.0/24\n</FilesMatch>"},
	{"filesmatch limit", "<Files \"a.php\">\n<Limit POST>\nRequire all denied\n</Limit>\n</Files>"},
}

func mapSig[V any](m map[string]V) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%v;", k, m[k])
	}
	return b.String()
}

func intMapSig(m map[int]string) string {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%d=%s;", k, m[k])
	}
	return b.String()
}

func parityBoolPtr(p *bool) string {
	if p == nil {
		return "nil"
	}
	return fmt.Sprint(*p)
}

// signature reads rs through every consumer and returns one line per reading.
func signature(rs *RuleSet) []string {
	var out []string
	add := func(k string, v any) { out = append(out, fmt.Sprintf("%s: %v", k, v)) }

	add("rewrite", fmt.Sprint(rs.RewriteEnabled, len(rs.Rewrites)))
	for _, r := range rs.Rewrites {
		add("rewrite rule", fmt.Sprint(r.Pattern, r.Target, r.Flags))
	}
	for _, r := range rs.Redirects {
		add("redirect", fmt.Sprint(r.Status, r.Pattern, r.Target, r.IsRegex))
	}
	for _, h := range rs.Headers {
		add("header", fmt.Sprint(h.Action, h.Name, h.Value, h.Env))
	}
	add("errordocs", intMapSig(rs.ErrorDocuments))
	add("errortexts", intMapSig(rs.ErrorTexts))
	add("directoryindex", rs.DirectoryIndex)
	add("listing", parityBoolPtr(rs.DirectoryListing))
	add("followsymlinks", parityBoolPtr(rs.FollowSymlinks))
	add("phpdisabled", parityBoolPtr(rs.PHPDisabled))
	add("auth", fmt.Sprint(rs.AuthType, rs.AuthName, rs.AuthUserFile, rs.AuthUserFileRejected)) // rs.Require is never read
	add("authrequired", AuthUserFileRequiresAuth(rs))
	add("expires", fmt.Sprint(rs.ExpiresActive, rs.ExpiresActiveSet, rs.ExpiresDefault, mapSig(rs.ExpiresByType)))
	add("mime", mapSig(rs.MimeTypes))
	add("phpvalues", mapSig(rs.PHPValues)+"|"+mapSig(rs.PHPFlags))
	add("access precomputed", rs.Access)
	for _, fb := range rs.FilesMatch {
		add("filesblock", fmt.Sprint(fb.Pattern, fb.IsGlob, fb.Uncertain))
	}

	ips := []string{"203.0.113.5", "198.51.100.7", ""}
	methods := []string{"GET", "POST", "HEAD", ""}
	uas := []string{"Bad", "Good"}
	files := []string{"a.php", "wp-config.php", "x.js", ".htaccess", "readme.txt"}
	for _, ip := range ips {
		var parsed net.IP
		if ip != "" {
			parsed = net.ParseIP(ip)
		}
		for _, m := range methods {
			for _, ua := range uas {
				attrs := &RequestAttrs{RemoteAddr: ip, Method: m, HTTPS: true, Header: http.Header{"User-Agent": {ua}}}
				add(fmt.Sprintf("access ip=%q m=%q ua=%s", ip, m, ua), rs.AccessForRequest(parsed, m, attrs))
				for _, f := range files {
					add(fmt.Sprintf("filesdeny ip=%q m=%q ua=%s f=%s", ip, m, ua, f),
						FilesMatchDeniesForRequest(rs, f, parsed, m, attrs))
				}
			}
		}
	}
	for _, f := range files {
		var hs []string
		for _, h := range rs.HeadersForFile(f) {
			hs = append(hs, fmt.Sprint(h.Action, h.Name, h.Value, h.Env))
		}
		add("headersforfile "+f, hs)
	}
	for _, f := range []string{"a.vec", "a.VEC", "a.css"} {
		add("mimetypefor "+f, rs.MimeTypeFor(f))
	}
	add("phpdisabledfor", PHPDisabledFor([]*RuleSet{rs}))

	eff := DirSettings([]*RuleSet{rs})
	add("dir expires", fmt.Sprint(eff.ExpiresActive, eff.ExpiresDefault, mapSig(eff.ExpiresByType)))
	add("dir mime", mapSig(eff.MimeTypes))
	add("dir index", eff.DirectoryIndex)
	add("dir errordocs", intMapSig(eff.ErrorDocuments))
	add("dir errortexts", intMapSig(eff.ErrorTexts))
	add("dir listing", parityBoolPtr(eff.DirectoryListing))
	return out
}

func parityRules(t *testing.T, src string) *RuleSet {
	t.Helper()
	ds, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	return Convert(ds)
}

func TestConditionalWrappersDoNotChangeWhatConsumersSee(t *testing.T) {
	for _, c := range parityCorpus {
		bare := signature(parityRules(t, c.rules+"\n"))
		for _, w := range activeWrappers {
			wrapped := signature(parityRules(t, w.open+"\n"+c.rules+"\n"+w.close+"\n"))
			if len(bare) != len(wrapped) {
				t.Errorf("%s inside %s: %d readings vs %d", c.name, w.name, len(bare), len(wrapped))
				continue
			}
			for i := range bare {
				if bare[i] != wrapped[i] {
					t.Errorf("%s inside %s differs:\n  bare:    %s\n  wrapped: %s", c.name, w.name, bare[i], wrapped[i])
				}
			}
		}
	}
}

// The control that keeps the comparison honest: an inactive section must change
// what the consumers see for the directives that do something, otherwise the
// signature would not notice a consumer ignoring the section.
func TestInactiveWrapperChangesWhatConsumersSee(t *testing.T) {
	changed := 0
	for _, c := range parityCorpus {
		bare := signature(parityRules(t, c.rules+"\n"))
		off := signature(parityRules(t, "<IfDefine UWAS_NO_SUCH_DEFINE>\n"+c.rules+"\n</IfDefine>\n"))
		for i := range bare {
			if i < len(off) && bare[i] != off[i] {
				changed++
				break
			}
		}
	}
	if min := len(parityCorpus) * 2 / 3; changed < min {
		t.Fatalf("only %d of %d directives read differently inside an inactive section; the signature has gone blind", changed, len(parityCorpus))
	}
}

// A directive wrapped inside a <FilesMatch> block must read the same as the
// bare one in that block for the per-file consumers.
func TestConditionalWrappersInsideAFilesBlock(t *testing.T) {
	inner := []string{
		"Require all denied",
		"Require ip 203.0.113.0/24",
		"Order Allow,Deny\nAllow from 203.0.113.0/24\nDeny from all",
		"SetEnvIf User-Agent \"Bad\" bad\nOrder Allow,Deny\nAllow from all\nDeny from env=bad",
		"<Limit POST>\nRequire all denied\n</Limit>",
		"Header set X-A 1",
		"Header always set X-B 2 env=HTTPS",
	}
	for _, body := range inner {
		bare := signature(parityRules(t, "<FilesMatch \"\\.(php|js)$\">\n"+body+"\n</FilesMatch>\n"))
		for _, w := range activeWrappers {
			wrapped := signature(parityRules(t, "<FilesMatch \"\\.(php|js)$\">\n"+w.open+"\n"+body+"\n"+w.close+"\n</FilesMatch>\n"))
			for i := range bare {
				if i >= len(wrapped) || bare[i] != wrapped[i] {
					got := "(missing)"
					if i < len(wrapped) {
						got = wrapped[i]
					}
					t.Errorf("%q inside %s inside a FilesMatch differs:\n  bare:    %s\n  wrapped: %s", body, w.name, bare[i], got)
				}
			}
		}
	}
}

// Equivalent spellings of the same rules must be read alike by every consumer.
func TestEquivalentSpellingsReadAlike(t *testing.T) {
	upperNames := func(src string) string {
		lines := strings.Split(src, "\n")
		for i, l := range lines {
			trim := strings.TrimLeft(l, " \t")
			switch {
			case trim == "":
			case strings.HasPrefix(trim, "</"):
				if j := strings.Index(trim, ">"); j > 0 {
					lines[i] = "</" + strings.ToUpper(trim[2:j]) + trim[j:]
				}
			case strings.HasPrefix(trim, "<"):
				if j := strings.IndexAny(trim, " >"); j > 0 {
					lines[i] = "<" + strings.ToUpper(trim[1:j]) + trim[j:]
				}
			default:
				if j := strings.IndexAny(trim, " \t"); j > 0 {
					lines[i] = strings.ToUpper(trim[:j]) + trim[j:]
				} else {
					lines[i] = strings.ToUpper(trim)
				}
			}
		}
		return strings.Join(lines, "\n")
	}
	spellings := []struct {
		name string
		f    func(string) string
	}{
		{"CRLF", func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }},
		{"BOM", func(s string) string { return "\ufeff" + s }},
		{"BOM and CRLF", func(s string) string { return "\ufeff" + strings.ReplaceAll(s, "\n", "\r\n") }},
		{"upper-case names", upperNames},
		{"tab separators", func(s string) string {
			// Only the blanks outside double quotes separate arguments.
			var b strings.Builder
			quoted := false
			for _, r := range s {
				if r == '"' {
					quoted = !quoted
				}
				if r == ' ' && !quoted {
					r = '\t'
				}
				b.WriteRune(r)
			}
			return b.String()
		}},
		{"blank lines and comments", func(s string) string { return "# header\n\n" + strings.ReplaceAll(s, "\n", "\n\n# note\n") }},
		{"trailing blanks", func(s string) string { return strings.ReplaceAll(s, "\n", "  \t\n") }},
		{"indented", func(s string) string { return "    " + strings.ReplaceAll(s, "\n", "\n    ") }},
	}
	for _, c := range parityCorpus {
		bare := signature(parityRules(t, c.rules+"\n"))
		for _, sp := range spellings {
			got := signature(parityRules(t, sp.f(c.rules+"\n")))
			for i := range bare {
				if i >= len(got) || bare[i] != got[i] {
					g := "(missing)"
					if i < len(got) {
						g = got[i]
					}
					t.Errorf("%s as %s differs:\n  plain:  %s\n  varied: %s", c.name, sp.name, bare[i], g)
				}
			}
		}
	}
}
