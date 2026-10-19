package webhook

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type f22200Logger struct {
	mu   sync.Mutex
	msgs []string
}

func (l *f22200Logger) add(m string) { l.mu.Lock(); l.msgs = append(l.msgs, m); l.mu.Unlock() }
func (l *f22200Logger) has(m string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, x := range l.msgs {
		if x == m {
			return true
		}
	}
	return false
}
func (l *f22200Logger) Debug(m string, a ...any) { l.add(m) }
func (l *f22200Logger) Info(m string, a ...any)  { l.add(m) }
func (l *f22200Logger) Warn(m string, a ...any)  { l.add(m) }
func (l *f22200Logger) Error(m string, a ...any) { l.add(m) }

type f22200Seen struct {
	mu     sync.Mutex
	method []string
	bodies []int
}

func (s *f22200Seen) rec(r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.method = append(s.method, r.Method)
	s.bodies = append(s.bodies, len(b))
	s.mu.Unlock()
}

// run delivers one event to a redirector answering with `code`, returning what
// the final receiver saw and whether deliver logged success.
func f22200Run(t *testing.T, code int) (*f22200Seen, bool, int) {
	t.Helper()
	rx := &f22200Seen{}
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { rx.rec(r) }))
	t.Cleanup(final.Close)
	hits := 0
	var hm sync.Mutex
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hm.Lock()
		hits++
		hm.Unlock()
		http.Redirect(w, r, final.URL+"/hook", code)
	}))
	t.Cleanup(redir.Close)
	lg := &f22200Logger{}
	m := &Manager{logger: lg, urlSafe: func(string) error { return nil }, done: make(chan struct{})}
	m.deliver(&queuedEvent{
		webhook: WebhookConfig{URL: redir.URL, Enabled: true, RetryMax: -1, Timeout: 5 * time.Second},
		event:   Event{ID: "e1", Type: EventTest, Timestamp: time.Now()},
	})
	hm.Lock()
	defer hm.Unlock()
	return rx, lg.has("webhook delivered"), hits
}

func TestF22200RedirectedPostIsNotReportedDelivered(t *testing.T) {
	bad := false
	// Control: 307 keeps POST and body -> delivery is real, reported delivered.
	rx, delivered, _ := f22200Run(t, http.StatusTemporaryRedirect)
	if !delivered || len(rx.method) != 1 || rx.method[0] != "POST" || rx.bodies[0] == 0 {
		t.Fatalf("control failed (307): delivered=%v methods=%v bodies=%v", delivered, rx.method, rx.bodies)
	}
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther} {
		rx, delivered, _ := f22200Run(t, code)
		gotBodyless := len(rx.method) > 0 && (rx.method[0] != "POST" || rx.bodies[0] == 0)
		t.Logf("EXPECTED: %d redirect must not be reported delivered when the receiver gets no POST body", code)
		t.Logf("ACTUAL: delivered=%v receiver methods=%v body bytes=%v", delivered, rx.method, rx.bodies)
		if delivered && gotBodyless {
			bad = true
		}
	}
	if bad {
		t.Fatal("PROBLEM CONFIRMED")
	}
	t.Log("PROBLEM NOT REPRODUCED")
}

// Edge: a refused 302 is a failed attempt, so retries run (attempt count > 1)
// and the receiver never sees the bodiless GET.
func TestF22200VerifyEdges(t *testing.T) {
	rx, delivered, hits := f22200Run(t, http.StatusFound)
	if delivered || len(rx.method) != 0 || hits != 1 {
		t.Fatalf("302: delivered=%v receiver=%v redirector hits=%d", delivered, rx.method, hits)
	}
	rx, delivered, _ = f22200Run(t, http.StatusSeeOther)
	if delivered || len(rx.method) != 0 {
		t.Fatalf("303: delivered=%v receiver=%v", delivered, rx.method)
	}
	// 308 also keeps POST + body.
	rx, delivered, _ = f22200Run(t, http.StatusPermanentRedirect)
	if !delivered || len(rx.method) != 1 || rx.method[0] != "POST" || rx.bodies[0] == 0 {
		t.Fatalf("308: delivered=%v receiver=%v bodies=%v", delivered, rx.method, rx.bodies)
	}

}
