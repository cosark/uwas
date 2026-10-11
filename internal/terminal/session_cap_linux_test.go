//go:build linux

package terminal

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// scOpen starts a terminal WebSocket against addr and returns the connection
// and the HTTP status line, tolerating a refusal (tdDial fails the test on
// anything but 101).
func scOpen(t *testing.T, addr string) (net.Conn, string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	req := "GET /terminal HTTP/1.1\r\nHost: " + addr + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Origin: http://" + addr + "\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	status, _ := bufio.NewReader(conn).ReadString('\n')
	return conn, strings.TrimSpace(status)
}

// F15202: a session is a shell, a PTY and goroutines; the handler refuses the
// session over its limit with a plain 503 (no upgrade), and a finished session
// makes room for the next.
func TestTerminalSessionsAreBounded(t *testing.T) {
	h := &Handler{Shell: tdScript(t, "exec sleep 600\n"), MaxSessions: 2}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	addr := ln.Addr().String()

	c1, st1 := scOpen(t, addr)
	defer c1.Close()
	c2, st2 := scOpen(t, addr)
	defer c2.Close()
	if !strings.Contains(st1, "101") || !strings.Contains(st2, "101") {
		t.Fatalf("sessions within the limit were refused: %q, %q", st1, st2)
	}

	c3, st3 := scOpen(t, addr)
	c3.Close()
	if !strings.Contains(st3, "503") {
		t.Fatalf("third session = %q, want 503 (limit is 2)", st3)
	}

	// Ending a session frees its slot. Teardown is asynchronous (the server
	// notices the closed socket, hangs the shell up and then returns), so poll
	// for the condition rather than sleeping.
	c1.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, st := scOpen(t, addr)
		if strings.Contains(st, "101") {
			c.Close()
			return
		}
		c.Close()
		if time.Now().After(deadline) {
			t.Fatalf("the slot of a finished session was never released (last status %q)", st)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestAcquireSessionDefaultsAndRelease(t *testing.T) {
	h := &Handler{}
	for i := 0; i < defaultMaxSessions; i++ {
		if !h.acquireSession() {
			t.Fatalf("session %d refused, default limit is %d", i, defaultMaxSessions)
		}
	}
	if h.acquireSession() {
		t.Fatalf("session over the default limit of %d was admitted", defaultMaxSessions)
	}
	h.releaseSession()
	if !h.acquireSession() {
		t.Fatal("a released slot was not reusable")
	}
}
