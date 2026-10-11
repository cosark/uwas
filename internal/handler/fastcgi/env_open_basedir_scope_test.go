package fastcgi

import (
	"strings"
	"testing"
)

// F11500: PHP treats an open_basedir entry as a string prefix, so every
// directory entry must end in "/" or "/var/www/site" also admits the sibling
// "/var/www/site.au".
func TestPerRequestOpenBasedirEntriesAreDirectoryScoped(t *testing.T) {
	for _, root := range []string{"/var/www/site", "/var/www/site/"} {
		d := adminDirectives(t, uploadEnv(t, root, 0))
		ob := d["open_basedir"]
		if ob == "" {
			t.Fatalf("root %q: no open_basedir", root)
		}
		entries := strings.Split(ob, ":")
		if entries[0] != "/var/www/site/" {
			t.Errorf("root %q: first entry %q, want /var/www/site/", root, entries[0])
		}
		for _, e := range entries {
			if strings.HasPrefix(e, "/var/www/") && !strings.HasSuffix(e, "/") {
				t.Errorf("root %q: entry %q is a bare prefix", root, e)
			}
		}
	}
}
