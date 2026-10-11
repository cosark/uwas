package fastcgi

import "testing"

// F8400: PATH_INFO is derived from the request path the way Apache and nginx
// deliver it: percent-decoded and with dot segments resolved.
func TestSplitScriptPathNormalizesPathInfo(t *testing.T) {
	const root = "/var/www"
	cases := []struct {
		uri, resolved, wantScript, wantInfo string
	}{
		{"/blog/../../../etc/passwd", "/var/www/index.php", "/index.php", "/etc/passwd"},
		{"/blog/%2e%2e/%2e%2e/etc/passwd", "/var/www/index.php", "/index.php", "/etc/passwd"},
		{"/blog/foo%20bar?x=1", "/var/www/index.php", "/index.php", "/blog/foo bar"},
		{"/blog/", "/var/www/index.php", "/index.php", "/blog/"},
		// Controls: unaffected shapes.
		{"/blog/post", "/var/www/index.php", "/index.php", "/blog/post"},
		{"/index.php/api/users", "/var/www/index.php", "/index.php", "/api/users"},
		{"/a.php", "/var/www/a.php", "/a.php", ""},
	}
	for _, c := range cases {
		script, info := SplitScriptPath(c.uri, c.resolved, root, []string{"index.php"})
		if script != c.wantScript || info != c.wantInfo {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", c.uri, script, info, c.wantScript, c.wantInfo)
		}
	}
}

func TestCGIPathKeepsControlCharactersEncoded(t *testing.T) {
	if got := cgiPath("/a/%00b"); got != "/a/%00b" {
		t.Errorf("cgiPath decoded a NUL: %q", got)
	}
	if got := cgiPath("/a/%zz"); got != "/a/%zz" {
		t.Errorf("cgiPath changed an undecodable path: %q", got)
	}
}
