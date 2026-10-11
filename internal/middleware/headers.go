package middleware

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
)

var securityHeaderValues = [4]string{
	"nosniff",
	"SAMEORIGIN",
	"strict-origin-when-cross-origin",
	"geolocation=(), microphone=(), camera=()",
}

// SecurityHeaders adds default security headers to all responses and keeps
// X-Powered-By off them.
//
// Each request owns its value array because handlers may mutate http.Header.
// One backing array avoids allocating a separate slice for each header.
func SecurityHeaders() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			values := securityHeaderValues
			h["X-Content-Type-Options"] = values[0:1:1]
			h["X-Frame-Options"] = values[1:2:2]
			h["Referrer-Policy"] = values[2:3:3]
			h["Permissions-Policy"] = values[3:4:4]
			delete(h, "X-Powered-By")

			// A backend or PHP-FPM sets X-Powered-By while it writes the
			// response, after the delete above, so strip it again as the status
			// is committed (F8820).
			next.ServeHTTP(&poweredByStripper{ResponseWriter: w}, r)
		})
	}
}

// poweredByStripper removes X-Powered-By from the header map just before the
// response headers are sent.
type poweredByStripper struct {
	http.ResponseWriter
	sent bool
}

func (w *poweredByStripper) commit(code int) {
	// Informational responses (100-199 except 101) do not commit the final headers.
	if w.sent || (code >= 100 && code < 200 && code != http.StatusSwitchingProtocols) {
		return
	}
	w.sent = true
	delete(w.ResponseWriter.Header(), "X-Powered-By")
}

func (w *poweredByStripper) WriteHeader(code int) {
	w.commit(code)
	w.ResponseWriter.WriteHeader(code)
}

func (w *poweredByStripper) Write(b []byte) (int, error) {
	w.commit(http.StatusOK)
	return w.ResponseWriter.Write(b)
}

func (w *poweredByStripper) Flush() {
	w.commit(http.StatusOK)
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *poweredByStripper) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("middleware: underlying ResponseWriter does not support Hijack")
	}
	return hj.Hijack()
}

// Unwrap exposes the underlying writer to http.ResponseController.
func (w *poweredByStripper) Unwrap() http.ResponseWriter { return w.ResponseWriter }
