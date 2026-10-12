package fastcgi

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// r129Serve accepts connections and runs h on each; it returns the address.
func r129Serve(t *testing.T, h func(c net.Conn, br *bufio.Reader)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(15 * time.Second))
				h(c, bufio.NewReader(c))
			}()
		}
	}()
	return "tcp:" + ln.Addr().String()
}

// r129ReadParams consumes records through the empty FCGI_PARAMS terminator.
func r129ReadParams(br *bufio.Reader) (params []byte, ok bool) {
	for {
		rec, err := ReadRecord(br)
		if err != nil {
			return nil, false
		}
		if rec.Type == TypeParams {
			if rec.ContentLength == 0 {
				return params, true
			}
			params = append(params, rec.Content...)
		}
	}
}

func r129End(bw *bufio.Writer, appStatus uint32, protocolStatus byte) {
	end := make([]byte, 8)
	binary.BigEndian.PutUint32(end, appStatus)
	end[4] = protocolStatus
	WriteRecord(bw, TypeEndRequest, 1, end)
	bw.Flush()
}

// A peer that refuses the request (FCGI_OVERLOADED / FCGI_CANT_MPX_CONN /
// FCGI_UNKNOWN_ROLE) did not run it. Reported as success the caller sees an
// empty response, indistinguishable from an application that printed nothing.
func TestExecuteProtocolStatusRefusalIsError(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status byte
		wantOK bool
	}{
		{"request_complete", 0, true},
		{"cant_mpx_conn", 1, false},
		{"overloaded", 2, false},
		{"unknown_role", 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := r129Serve(t, func(c net.Conn, br *bufio.Reader) {
				if _, ok := r129ReadParams(br); !ok {
					return
				}
				bw := bufio.NewWriter(c)
				if tc.wantOK {
					WriteRecord(bw, TypeStdout, 1, []byte("Status: 200\r\n\r\nok"))
				}
				r129End(bw, 0, tc.status)
			})
			client := NewClient(PoolConfig{Address: addr, MaxIdle: 1, MaxOpen: 1})
			defer client.Close()
			resp, err := client.Execute(context.Background(), map[string]string{"SCRIPT_FILENAME": "/t.php"}, nil)
			if tc.wantOK {
				if err != nil || resp == nil || !strings.Contains(string(resp.Stdout()), "ok") {
					t.Fatalf("control: want success, got resp=%v err=%v", resp, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("EXPECTED: error for protocolStatus=%d\nACTUAL: success, stdout=%q", tc.status, resp.Stdout())
			}
			if !errors.Is(err, ErrRequestRejected) {
				t.Fatalf("want ErrRequestRejected, got %v", err)
			}
			if active, idle := client.pool.Stats(); active != 0 || idle != 0 {
				t.Fatalf("refused connection must be discarded: active=%d idle=%d", active, idle)
			}
		})
	}
}

// gatedReader blocks in Read until released, like a client that stopped
// sending its upload.
type gatedReader struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func newGatedReader() *gatedReader {
	return &gatedReader{started: make(chan struct{}), release: make(chan struct{})}
}

func (g *gatedReader) Read(p []byte) (int, error) {
	g.once.Do(func() { close(g.started) })
	<-g.release
	return 0, io.ErrUnexpectedEOF
}

func r129WaitGoroutines(t *testing.T, base int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= base {
			return
		}
		runtime.Gosched()
		time.Sleep(5 * time.Millisecond)
	}
	buf := make([]byte, 1<<16)
	t.Fatalf("goroutines did not return to baseline %d: now %d\n%s", base, runtime.NumGoroutine(), buf[:runtime.Stack(buf, true)])
}

// The request context bounds Execute. A client that stalls mid-upload must
// not keep Execute (and its pool slot) past that deadline just because the
// body reader is parked in Read.
func TestExecuteContextDeadlineWithBlockedBodyReader(t *testing.T) {
	hold := make(chan struct{})
	addr := r129Serve(t, func(c net.Conn, br *bufio.Reader) {
		r129ReadParams(br)
		<-hold // never answers
	})
	var holdOnce sync.Once
	releaseServer := func() { holdOnce.Do(func() { close(hold) }) }
	defer releaseServer()
	client := NewClient(PoolConfig{Address: addr, MaxIdle: 1, MaxOpen: 1})
	defer client.Close()
	base := runtime.NumGoroutine()

	g := newGatedReader()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err = client.Execute(ctx, map[string]string{"SCRIPT_FILENAME": "/t.php"}, g)
	}()
	<-g.started
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		close(g.release)
		<-done
		t.Fatalf("EXPECTED: Execute returns shortly after the 300ms context deadline\nACTUAL: still blocked 5s later, waiting for the body reader")
	}
	if err == nil {
		t.Fatal("want deadline error")
	}
	if active, _ := client.pool.Stats(); active != 0 {
		t.Fatalf("pool slot still held after Execute returned: active=%d", active)
	}
	close(g.release)
	releaseServer()
	r129WaitGoroutines(t, base)
}

// An application that has already answered must not be waited on for the
// rest of a body the client is no longer sending.
func TestExecuteEarlyAnswerWithBlockedBodyReader(t *testing.T) {
	hold := make(chan struct{})
	addr := r129Serve(t, func(c net.Conn, br *bufio.Reader) {
		r129ReadParams(br)
		bw := bufio.NewWriter(c)
		WriteRecord(bw, TypeStdout, 1, []byte("Status: 413 Payload Too Large\r\n\r\nno"))
		r129End(bw, 0, 0)
		<-hold
	})
	var holdOnce sync.Once
	releaseServer := func() { holdOnce.Do(func() { close(hold) }) }
	defer releaseServer()
	client := NewClient(PoolConfig{Address: addr, MaxIdle: 1, MaxOpen: 1})
	defer client.Close()
	base := runtime.NumGoroutine()

	g := newGatedReader()
	var resp *Response
	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err = client.Execute(context.Background(), map[string]string{"SCRIPT_FILENAME": "/t.php"}, g)
	}()
	<-g.started
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		close(g.release)
		<-done
		t.Fatalf("EXPECTED: the early 413 is returned while the body reader is stalled\nACTUAL: Execute blocked 5s on the reader")
	}
	if err != nil || resp == nil || !strings.Contains(string(resp.Stdout()), "413") {
		t.Fatalf("want the early response, got resp=%v err=%v", resp, err)
	}
	if active, idle := client.pool.Stats(); active != 0 || idle != 0 {
		t.Fatalf("half-written connection must not be pooled: active=%d idle=%d", active, idle)
	}
	close(g.release)
	releaseServer()
	r129WaitGoroutines(t, base)
}

// Names and values of every size class, with bytes that are control
// characters in HTTP, must reach the peer byte-for-byte: the encoding is
// length-prefixed, so nothing may be interpreted, split or dropped.
func TestExecuteParamsRoundTripBinarySafe(t *testing.T) {
	env := map[string]string{
		"SCRIPT_FILENAME":        "/t.php",
		"HTTP_CRLF":              "a\r\nSet-Cookie: x=1\r\n\r\n",
		"HTTP_NUL":               "a\x00b",
		"HTTP_EMPTY":             "",
		"HTTP_127":               strings.Repeat("a", 127),
		"HTTP_128":               strings.Repeat("b", 128),
		"HTTP_HUGE":              strings.Repeat("c", 200000), // spans several records
		strings.Repeat("N", 300): "long-name",
	}
	for i := 0; i < 40; i++ {
		env["HTTP_FILL_"+strings.Repeat("x", i)] = strings.Repeat("v", 3000+i)
	}
	got := make(chan map[string]string, 1)
	addr := r129Serve(t, func(c net.Conn, br *bufio.Reader) {
		p, ok := r129ReadParams(br)
		if !ok {
			return
		}
		m, err := DecodeParams(p)
		if err != nil {
			m = map[string]string{"decode error": err.Error()}
		}
		got <- m
		bw := bufio.NewWriter(c)
		WriteRecord(bw, TypeStdout, 1, []byte("Status: 200\r\n\r\n"))
		r129End(bw, 0, 0)
	})
	client := NewClient(PoolConfig{Address: addr, MaxIdle: 1, MaxOpen: 1})
	defer client.Close()
	if _, err := client.Execute(context.Background(), env, nil); err != nil {
		t.Fatal(err)
	}
	m := <-got
	if len(m) != len(env) {
		t.Fatalf("param count: got %d want %d (%v)", len(m), len(env), m["decode error"])
	}
	for k, v := range env {
		if m[k] != v {
			t.Fatalf("param %.20q altered in transit (len %d -> %d)", k, len(v), len(m[k]))
		}
	}
}

// Backend response text is untrusted input to the HTTP layer: CR/NUL
// inside a header value must not survive parsing, and a status line that is
// not a status must not become one.
func TestParseHTTPHostileResponses(t *testing.T) {
	parse := func(s string) (int, map[string][]string, string) {
		r := &Response{}
		r.stdout.WriteString(s)
		code, h, b := r.ParseHTTP()
		body, _ := io.ReadAll(b)
		return code, h, string(body)
	}
	for name, in := range map[string]string{
		"bare CR in value":  "Status: 200\r\nX-A: a\rSet-Cookie: x=1\r\n\r\nbody",
		"NUL in value":      "X-A: a\x00b\r\n\r\nbody",
		"NUL in header key": "X\x00A: a\r\n\r\nbody",
	} {
		code, h, body := parse(in)
		if code != 502 || len(h) != 0 || body != "" {
			t.Errorf("%s: want 502/no headers/no body, got %d %v %q", name, code, h, body)
		}
	}
	// Obsolete line folding must fold into the previous header's value and
	// never start a new header (it would otherwise smuggle Set-Cookie).
	code, h, _ := parse("Status: 200\r\nX-A: a\r\n Set-Cookie: x=1\r\n\r\nbody")
	if code != 200 || h["Set-Cookie"] != nil {
		t.Errorf("folded line became a header: %d %v", code, h)
	}
	// Headers without a body, bare-LF terminators.
	if code, _, body := parse("Status: 204\r\n\r\n"); code != 204 || body != "" {
		t.Errorf("no-body response: %d %q", code, body)
	}
	if code, h, body := parse("Status: 200\nContent-Type: a\n\nbody"); code != 200 || h["Content-Type"][0] != "a" || body != "body" {
		t.Errorf("bare LF response: %d %v %q", code, h, body)
	}
}
