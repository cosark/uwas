package proxy

import (
	"bufio"
	"strings"
	"testing"
)

// TestUpgradeHeadAcceptsLongHeaderLines pins readUpgradeResponseHead against
// the reader the tunnel builds (bufio.NewReader, 4096-byte buffer). The head is
// capped at maxUpgradeResponseHead (64 KiB) as a whole, so a single header line
// longer than the reader's buffer — a large Set-Cookie or Link on a rejected
// upgrade — must be relayed, not turned into a 502 by bufio.ErrBufferFull.
func TestUpgradeHeadAcceptsLongHeaderLines(t *testing.T) {
	const status = "HTTP/1.1 101 Switching Protocols\r\n"
	build := func(lines ...string) string {
		return status + strings.Join(lines, "") + "\r\n"
	}

	cases := []struct {
		name string
		head string
		ok   bool
	}{
		// control: a short head is read verbatim.
		{"control short header", build("Upgrade: websocket\r\n", "X-Short: "+strings.Repeat("a", 100)+"\r\n"), true},
		{"long header line", build("Upgrade: websocket\r\n", "X-Long: "+strings.Repeat("a", 5000)+"\r\n"), true},
		// The line's content fills the 4096-byte buffer exactly, so its CRLF
		// arrives alone in the next read: that must not end the head early.
		{"crlf alone at buffer boundary", build("X-Edge: "+strings.Repeat("b", 4096-len("X-Edge: "))+"\r\n", "Upgrade: websocket\r\n"), true},
		{"several long lines under the cap", build(
			"X-A: "+strings.Repeat("c", 9000)+"\r\n",
			"X-B: "+strings.Repeat("d", 9000)+"\r\n",
			"Upgrade: websocket\r\n"), true},
		// control for the cap: the head as a whole is still bounded.
		{"over the 64KiB cap", build("X-Huge: " + strings.Repeat("e", maxUpgradeResponseHead+10) + "\r\n"), false},
	}

	problems := 0
	for _, tc := range cases {
		head, code, err := readUpgradeResponseHead(bufio.NewReader(strings.NewReader(tc.head)))
		switch {
		case tc.ok && err != nil:
			problems++
			t.Errorf("%s:\nEXPECTED: head of %d bytes read verbatim, status 101\nACTUAL:   err=%v", tc.name, len(tc.head), err)
		case tc.ok && (code != 101 || string(head) != tc.head):
			problems++
			t.Errorf("%s:\nEXPECTED: head of %d bytes read verbatim, status 101\nACTUAL:   %d bytes, status %d (truncated=%v)", tc.name, len(tc.head), len(head), code, len(head) < len(tc.head))
		case !tc.ok && err == nil:
			problems++
			t.Errorf("%s:\nEXPECTED: error for a head over the cap\nACTUAL:   accepted %d bytes", tc.name, len(head))
		}
	}
	if problems > 0 {
		t.Logf("PROBLEM CONFIRMED (%d case(s))", problems)
		return
	}
	t.Log("PROBLEM NOT REPRODUCED")
}
