package fastcgi

import "testing"

// F4800: SCRIPT_NAME detection must treat .PHP like .php, otherwise a request
// for /Conf.PHP runs index.php with PATH_INFO=/Conf.PHP.
func TestSplitScriptPathUppercaseExtension(t *testing.T) {
	root := "/srv/site"
	for _, name := range []string{"/x.php", "/X.PHP", "/X.Php"} {
		sn, pi := SplitScriptPath(name, root+name, root, []string{"index.php"})
		if sn != name || pi != "" {
			t.Errorf("%s: script=%q pathinfo=%q, want %q and empty", name, sn, pi, name)
		}
	}
}
