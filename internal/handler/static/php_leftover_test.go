package static

import "testing"

func TestIsPHPSourceLeftover(t *testing.T) {
	for name, want := range map[string]bool{
		"wp-config.php.bak": true, "a.php~": true, "a.php.old": true, "a.phps": true, "A.PHP.BAK": true,
		"a.php.swp": true, "a.php.orig": true,
		"a.php": false, "a.phpx": false, "b.php.txt": false, "notes.txt.bak": false, "db.sql": false,
		"a.php.bakery": false, "file~": false, "report.old": false, "": false,
	} {
		if got := IsPHPSourceLeftover(name); got != want {
			t.Errorf("IsPHPSourceLeftover(%q) = %v, want %v", name, got, want)
		}
	}
}
