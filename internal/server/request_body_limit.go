package server

import (
	"net/http"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/router"
	"github.com/uwaserver/uwas/pkg/htaccess"
)

// enforceRequestBodyLimit applies "LimitRequestBody" from the .htaccess levels
// on the request path: a body whose declared length is over the cap is refused
// with 413 before anything reads it, and a body of unknown length (chunked) is
// cut off once it passes the cap. It reports whether the request was answered.
// The directive is protective, so like Require it holds whatever htaccess.mode
// says (F16901).
func (s *Server) enforceRequestBodyLimit(ctx *router.RequestContext, domain *config.Domain) bool {
	r := ctx.Request
	if r.Body == nil || r.Body == http.NoBody {
		return false
	}
	limit := htaccess.LimitRequestBodyFor(s.htaccessDirChain(domain, r.URL.Path))
	if limit <= 0 {
		return false
	}
	if r.ContentLength > limit {
		s.renderDomainErrorFor(r, ctx.Response, http.StatusRequestEntityTooLarge, domain)
		return true
	}
	if r.ContentLength < 0 {
		r.Body = http.MaxBytesReader(ctx.Response, r.Body, limit)
	}
	return false
}
