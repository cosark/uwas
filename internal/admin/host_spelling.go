package admin

import "github.com/uwaserver/uwas/internal/config"

// sameConfiguredHost reports whether a request's host path value names the
// configured domain host. Access to a {domain} route is decided on the
// canonical spelling of the host (case, a trailing dot, "bücher.example" and
// its punycode form: CanManageDomain), so the lookup that picks the domain's
// root must use the same equivalence. An exact comparison missed the
// configured domain for any other spelling and the caller fell back to a
// directory or PHP pool named after the spelling it typed (F13400).
func sameConfiguredHost(configured, requested string) bool {
	if configured == requested {
		return true
	}
	c := config.CanonicalHost(configured)
	return c != "" && c == config.CanonicalHost(requested)
}
