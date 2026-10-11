package server

import (
	"net/http"
	"time"
)

// readDeadline gives a request the read limit http.Server.ReadTimeout enforces
// on the TCP listeners. quic-go's http3.Server has no such field, so a client
// that stalled the request body held its handler, its connection slot and the
// upstream connection until the QUIC idle timer ended, which a client that keeps
// the connection alive never lets happen (F15000). d <= 0 leaves it alone.
func readDeadline(next http.Handler, d time.Duration) http.Handler {
	if d <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(d))
		next.ServeHTTP(w, r)
	})
}
