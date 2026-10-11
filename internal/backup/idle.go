package backup

import (
	"context"
	"io"
	"os"
	"time"
)

// opIdleTimeout is how long a backup transfer may go without moving a byte
// before it is abandoned. A fixed absolute cap (it used to be 5 minutes for the
// archive and the upload together, plus the same again on the S3 HTTP client)
// failed every backup that was merely large while it was still making steady
// progress (F9810).
var opIdleTimeout = 5 * time.Minute

// newIdleContext returns a context that is cancelled once idle has passed
// without touch being called, a touch func that restarts the countdown, and a
// cancel func that releases the timer.
func newIdleContext(parent context.Context, idle time.Duration) (context.Context, func(), context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	timer := time.AfterFunc(idle, cancel)
	return ctx, func() { timer.Reset(idle) }, func() {
		timer.Stop()
		cancel()
	}
}

// progressReader restarts an idle countdown whenever bytes are read through it.
type progressReader struct {
	r     io.Reader
	touch func()
	file  *os.File // set when r is a regular file, so providers can size the body
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.touch()
	}
	return n, err
}

// BackingFile returns the file the reader wraps, or nil.
func (p *progressReader) BackingFile() *os.File { return p.file }
