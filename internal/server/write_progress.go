package server

import (
	"bufio"
	"net"
	"net/http"
	"time"
)

// writeChunk bounds how much one Write may hand to the connection under a
// single deadline, so a large body to a slow client is judged per chunk.
const writeChunk = 64 << 10

// writeProgress turns global.timeouts.write from a deadline on the whole
// response into a deadline on each write: http.Server.WriteTimeout is
// absolute, so an SSE stream or a long download to a slow client that keeps
// making progress was cut when it elapsed (F8700). Every write (and flush)
// pushes the deadline out by d again; a client that stops reading still hits
// it. d <= 0 leaves the server's own behaviour alone.
func writeProgress(next http.Handler, d time.Duration) http.Handler {
	if d <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&progressWriter{ResponseWriter: w, rc: http.NewResponseController(w), d: d}, r)
	})
}

type progressWriter struct {
	http.ResponseWriter
	rc *http.ResponseController
	d  time.Duration
}

func (p *progressWriter) extend() { _ = p.rc.SetWriteDeadline(time.Now().Add(p.d)) }

func (p *progressWriter) WriteHeader(code int) {
	p.extend()
	p.ResponseWriter.WriteHeader(code)
}

func (p *progressWriter) Write(b []byte) (int, error) {
	written := 0
	for {
		n := len(b)
		if n > writeChunk {
			n = writeChunk
		}
		p.extend()
		m, err := p.ResponseWriter.Write(b[:n])
		written += m
		if err != nil || n == len(b) {
			return written, err
		}
		b = b[n:]
	}
}

func (p *progressWriter) Flush() {
	p.extend()
	_ = p.rc.Flush()
}

func (p *progressWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) { return p.rc.Hijack() }

// Unwrap lets http.ResponseController reach the server's own writer.
func (p *progressWriter) Unwrap() http.ResponseWriter { return p.ResponseWriter }
