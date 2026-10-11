package static

import (
	"net/http"

	"github.com/uwaserver/uwas/internal/router"
)

// allowedMethods are the methods a file or a directory listing is served for.
// nginx's static module and Apache's default handler answer the same set and
// refuse the rest with 405.
const allowedMethods = "GET, HEAD, POST, OPTIONS"

// ServesMethod reports whether a static file may be written to the response
// for the request's method. For any other method it has already answered and
// the caller must stop: OPTIONS gets the allowed set without a body, and every
// other method gets 405.
//
// Without it, a PUT or DELETE of an existing file was answered 200 with the
// whole file, so a client was told its write succeeded while nothing changed,
// and an OPTIONS probe of a large file received the file (F15600).
func ServesMethod(ctx *router.RequestContext) bool {
	switch ctx.Request.Method {
	case "", http.MethodGet, http.MethodHead, http.MethodPost:
		return true
	case http.MethodOptions:
		ctx.Response.Header().Set("Allow", allowedMethods)
		ctx.Response.Header().Set("Content-Length", "0")
		ctx.Response.WriteHeader(http.StatusOK)
		return false
	}
	ctx.Response.Header().Set("Allow", allowedMethods)
	ctx.Response.Error(http.StatusMethodNotAllowed, "405 Method Not Allowed")
	return false
}
