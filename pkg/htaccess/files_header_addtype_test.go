package htaccess

import (
	"strings"
	"testing"
)

func convertSrc(t *testing.T, src string) *RuleSet {
	t.Helper()
	ds, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	return Convert(ds)
}

func headerNames(hs []HeaderRule) []string {
	var out []string
	for _, h := range hs {
		out = append(out, h.Name)
	}
	return out
}

// F9100: Header directives inside <FilesMatch>/<Files> were dropped, so a
// per-file header never reached the response.
func TestHeadersForFileAppliesOnlyToMatchingFiles(t *testing.T) {
	rs := convertSrc(t, `Header set X-Top top
<FilesMatch "\.(js|css)$">
Header set Cache-Control "max-age=3600"
Header always set X-Content-Type-Options nosniff
</FilesMatch>
<Files robots.txt>
Header unset X-Powered-By
</Files>
<IfModule mod_headers.c>
<FilesMatch "\.html$">
Header set X-Html yes
</FilesMatch>
</IfModule>
`)
	cases := []struct {
		file string
		want []string
	}{
		{"app.js", []string{"Cache-Control", "X-Content-Type-Options"}},
		{"site.css", []string{"Cache-Control", "X-Content-Type-Options"}},
		{"robots.txt", []string{"X-Powered-By"}},
		{"index.html", []string{"X-Html"}},
		{"readme.txt", nil}, // control: matches no block
	}
	for _, c := range cases {
		got := headerNames(rs.HeadersForFile(c.file))
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: headers %v, want %v", c.file, got, c.want)
		}
	}
	if len(rs.Headers) != 1 || rs.Headers[0].Name != "X-Top" {
		t.Errorf("top-level headers = %+v, want only X-Top", rs.Headers)
	}
}

func TestHeadersForFileSkipsUndecidableAndUncompilable(t *testing.T) {
	rs := convertSrc(t, `<If "%{HTTP_HOST} == 'a.example'">
<FilesMatch "\.js$">
Header set X-Undecided 1
</FilesMatch>
</If>
<FilesMatch "^(?!index)\.js$">
Header set X-Uncompilable 1
</FilesMatch>
<FilesMatch "\.js$">
Header set X-Ok 1 env=!NOHDR
</FilesMatch>
`)
	got := rs.HeadersForFile("app.js")
	if len(got) != 1 || got[0].Name != "X-Ok" || got[0].Env != "!NOHDR" {
		t.Fatalf("headers = %+v, want only X-Ok carrying its env condition", got)
	}
}

func TestHeadersForFileSurvivesMerge(t *testing.T) {
	parent := convertSrc(t, "<FilesMatch \"\\.js$\">\nHeader set X-Parent 1\n</FilesMatch>\n")
	child := convertSrc(t, "<FilesMatch \"\\.js$\">\nHeader set X-Child 1\n</FilesMatch>\n")
	parent.Merge(child)
	if got := headerNames(parent.HeadersForFile("a.js")); strings.Join(got, ",") != "X-Parent,X-Child" {
		t.Errorf("merged headers = %v", got)
	}
	var nilSet *RuleSet
	if nilSet.HeadersForFile("a.js") != nil || nilSet.MimeTypeFor("a.js") != "" {
		t.Error("nil RuleSet must be inert")
	}
}

// F9101: AddType was ignored.
func TestMimeTypeForHonoursAddType(t *testing.T) {
	rs := convertSrc(t, `AddType image/svg+xml .svg .SVGZ
AddType application/manifest+json webmanifest
AddType text/plain .txt
`)
	cases := map[string]string{
		"logo.svg":      "image/svg+xml",
		"LOGO.SVG":      "image/svg+xml",
		"logo.svgz":     "image/svg+xml",
		"a.webmanifest": "application/manifest+json",
		"a.txt":         "text/plain",
		"a.js":          "", // control: no mapping
		"noext":         "",
	}
	for file, want := range cases {
		if got := rs.MimeTypeFor(file); got != want {
			t.Errorf("MimeTypeFor(%q) = %q, want %q", file, got, want)
		}
	}
	parent := convertSrc(t, "AddType text/plain .txt .log\n")
	parent.Merge(convertSrc(t, "AddType text/x-child .txt\n"))
	if parent.MimeTypeFor("a.txt") != "text/x-child" || parent.MimeTypeFor("a.log") != "text/plain" {
		t.Error("a child directory's AddType must override only its own extension")
	}
}

// F9102: ExpiresDefault was dropped, so every type ExpiresByType does not name
// got no lifetime at all.
func TestExpiresDefaultRetainedAndMerged(t *testing.T) {
	rs := convertSrc(t, "ExpiresActive On\nExpiresByType text/html \"access plus 1 hour\"\nExpiresDefault \"access plus 1 month\"\n")
	if rs.ExpiresDefault != "access plus 1 month" || rs.ExpiresByType["text/html"] != "access plus 1 hour" {
		t.Fatalf("ExpiresDefault=%q ByType=%v", rs.ExpiresDefault, rs.ExpiresByType)
	}
	if got := convertSrc(t, "ExpiresDefault A300\n").ExpiresDefault; got != "A300" {
		t.Errorf("compact form = %q, want A300", got)
	}
	rs.Merge(convertSrc(t, "ExpiresDefault \"access plus 2 days\"\n"))
	if rs.ExpiresDefault != "access plus 2 days" {
		t.Errorf("child ExpiresDefault must override, got %q", rs.ExpiresDefault)
	}
	rs.Merge(convertSrc(t, "Header set X 1\n"))
	if rs.ExpiresDefault != "access plus 2 days" {
		t.Errorf("a child without ExpiresDefault must keep the parent's, got %q", rs.ExpiresDefault)
	}
}
