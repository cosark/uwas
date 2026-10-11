package sftpserver

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

// bannerServed reports whether the server took the connection on: an accepted
// connection speaks first (SSH version banner), a refused one is closed
// without a byte.
func bannerServed(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4)
	n, err := c.Read(buf)
	return err == nil && n == 4 && string(buf) == "SSH-"
}

// startLimited is startTestServer with connection limits set on the Config.
func startLimited(t *testing.T, handshakes, perSource, sessions int) (*Server, string) {
	t.Helper()
	cfg := Config{
		Listen:                 "127.0.0.1:0",
		HostKey:                filepath.Join(t.TempDir(), "host_key"),
		Users:                  map[string]User{"u": {Password: string(testHash(t, "pw")), Root: t.TempDir()}},
		MaxHandshakes:          handshakes,
		MaxHandshakesPerSource: perSource,
		MaxSessionsPerConn:     sessions,
	}
	s := New(cfg, testLogger())
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return s, s.listener.Addr().String()
}

func testHash(t *testing.T, pw string) []byte {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// F15200: connections that have not finished the SSH handshake are bounded,
// per source and overall, and a slot comes back when its connection goes away.
func TestUnauthenticatedConnectionsAreBounded(t *testing.T) {
	s, addr := startLimited(t, 4, 2, 0)
	defer s.Stop()

	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		return c
	}

	// One at a time: connections are admitted by separate goroutines, so
	// dialing all three first would let the third overtake the others.
	first := dial()
	if !bannerServed(first) {
		t.Fatal("first connection was not served")
	}
	if !bannerServed(dial()) {
		t.Fatal("second connection, within the per-source limit, was not served")
	}
	if bannerServed(dial()) {
		t.Error("a third unauthenticated connection from one source was served, per-source limit is 2")
	}

	// Closing a served connection frees its slot.
	first.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if bannerServed(dial()) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the slot of a closed connection was never given back")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// F15200: the slot is released when the handshake finishes, not when the
// connection ends, so an authenticated client that stays connected never
// blocks the next login from the same address.
func TestHandshakeSlotReleasedAfterLogin(t *testing.T) {
	// Two slots per source and three logins that all stay connected: had a
	// slot been held until its connection ended, the third login would be
	// refused. (A slot is given back just after the client sees the handshake
	// finish, so one login can still be releasing while the next is admitted;
	// that is why the limit is 2 and not 1.)
	s, addr := startLimited(t, 4, 2, 0)
	defer s.Stop()

	for i := 0; i < 3; i++ {
		c, err := ssh.Dial("tcp", addr, sshClientConfig("u", "pw"))
		if err != nil {
			t.Fatalf("login %d while earlier ones are still connected: %v", i+1, err)
		}
		defer c.Close()
	}
}

func TestSourceKeyGroupsIPv6By64(t *testing.T) {
	addr := func(s string) net.Addr {
		a, err := net.ResolveTCPAddr("tcp", s)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	k1, ok1 := sourceKey(addr("[2001:db8:1:2::1]:22"))
	k2, ok2 := sourceKey(addr("[2001:db8:1:2:ffff::9]:22"))
	k3, _ := sourceKey(addr("[2001:db8:1:3::1]:22"))
	if !ok1 || !ok2 || k1 != k2 {
		t.Errorf("addresses in one /64 got different keys: %q, %q", k1, k2)
	}
	if k1 == k3 {
		t.Errorf("addresses in different /64s share key %q", k1)
	}
	if k, _ := sourceKey(addr("1.2.3.4:5")); k != "1.2.3.4" {
		t.Errorf("IPv4 key = %q", k)
	}
	if k, _ := sourceKey(addr("[::ffff:1.2.3.4]:5")); k != "1.2.3.4" {
		t.Errorf("IPv4-mapped key = %q, want the IPv4 address", k)
	}
	if _, ok := sourceKey(nil); ok {
		t.Error("nil address produced a key")
	}
}

// F15201: an authenticated connection may hold only so many session channels
// open, and closing one makes room for another.
func TestSessionChannelsPerConnectionAreBounded(t *testing.T) {
	s, addr := startLimited(t, 0, 0, 3)
	defer s.Stop()

	cli, err := ssh.Dial("tcp", addr, sshClientConfig("u", "pw"))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer cli.Close()

	var chans []ssh.Channel
	for i := 0; i < 3; i++ {
		ch, _, err := cli.OpenChannel("session", nil)
		if err != nil {
			t.Fatalf("channel %d within the limit refused: %v", i, err)
		}
		chans = append(chans, ch)
	}
	if _, _, err := cli.OpenChannel("session", nil); err == nil {
		t.Fatal("a fourth session channel was accepted, the limit is 3")
	}

	chans[0].Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		ch, _, err := cli.OpenChannel("session", nil)
		if err == nil {
			ch.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("closing a channel never made room for another: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
