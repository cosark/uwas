package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/uwaserver/uwas/internal/logger"
)

// F9610: copies of wp-config.php (editor and operator backups) are served as
// plain text, database credentials included; the default list only named
// wp-config.php itself.
func TestSecurityGuardBlocksWPConfigCopies(t *testing.T) {
	h := SecurityGuard(logger.New("error", "text"), nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	code := func(p string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		return rec.Code
	}
	for _, p := range []string{
		"/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.save", "/wp-config.php.old",
		"/wp-config.php.orig", "/wp-config.php.swp", "/wp-config.php.txt", "/wp-config.bak",
		"/wp-config.old", "/blog/wp-config.php.bak", "/WP-CONFIG.PHP.BAK", "/wp-config.php",
	} {
		if got := code(p); got != http.StatusForbidden {
			t.Errorf("%s = %d, want 403", p, got)
		}
	}
	// Controls: the shipped sample, look-alikes and other files' backups (the
	// WAF's file_probe family, opt-in) stay served by this always-on guard.
	for _, p := range []string{
		"/", "/index.php", "/wp-config-sample.php", "/wp-config-tutorial.html", "/readme.txt",
		"/index.php.bak", "/index.php~", "/backup/", "/old/wp-config.php.bak/index.html",
	} {
		if got := code(p); got != http.StatusOK {
			t.Errorf("%s = %d, want 200", p, got)
		}
	}
}
