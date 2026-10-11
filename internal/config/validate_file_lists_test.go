package config

import (
	"fmt"
	"strings"
	"testing"
)

// F14403: try_files, index_files and php.index_files are tried one stat at a
// time for every request, and a reseller sets them for their own domain; an
// unbounded list made each request cost ~17 us per entry (1.8 s for 100k).
func TestValidateBoundsFileResolutionLists(t *testing.T) {
	names := func(n int) []string {
		l := make([]string, n)
		for i := range l {
			l[i] = fmt.Sprintf("$uri.v%d", i)
		}
		return l
	}
	mk := func(try, index, phpIndex int) *Domain {
		d := &Domain{Host: "t.example", Type: "static", Root: "/srv/www/t", TryFiles: names(try), IndexFiles: names(index)}
		d.PHP.IndexFiles = names(phpIndex)
		return d
	}
	if err := ValidateDomainPartial(mk(MaxTryFiles, MaxIndexFiles, MaxIndexFiles)); err != nil {
		t.Fatalf("control: lists at the limit rejected: %v", err)
	}
	if err := ValidateDomainPartial(mk(3, 2, 0)); err != nil {
		t.Fatalf("control: ordinary lists rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		d    *Domain
		want string
	}{
		{"try_files", mk(MaxTryFiles+1, 0, 0), "try_files"},
		{"index_files", mk(0, MaxIndexFiles+1, 0), "index_files"},
		{"php.index_files", mk(0, 0, MaxIndexFiles+1), "php.index_files"},
		{"100k try_files", mk(100000, 0, 0), "try_files"},
	} {
		if err := ValidateDomainPartial(tc.d); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s over the limit: err = %v, want a refusal naming %s", tc.name, err, tc.want)
		}
	}
}
