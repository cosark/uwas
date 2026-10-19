package server

import (
	"net"
	"strings"
	"testing"
)

// A PROXY TCP6 source must become a RemoteAddr that net.SplitHostPort can
// parse; without brackets "2001:db8::1:5555" is "too many colons" and every
// per-IP consumer lost the client address (F20600).
func TestProxyProtoV6RemoteAddrIsSplittable(t *testing.T) {
	for _, tc := range []struct{ hdr, wantHost, wantPort string }{
		{"PROXY TCP4 192.0.2.9 10.0.0.1 5555 443\r\nGET / HTTP/1.1\r\n", "192.0.2.9", "5555"},
		{"PROXY TCP6 2001:db8::1 2001:db8::2 5555 443\r\nGET / HTTP/1.1\r\n", "2001:db8::1", "5555"},
		{"PROXY TCP6 ::1 ::2 1 443\r\nGET / HTTP/1.1\r\n", "::1", "1"},
	} {
		c := &proxyProtoConn{Conn: &boundedFeedConn{src: strings.NewReader(tc.hdr), limit: 1 << 20}}
		host, port, err := net.SplitHostPort(c.RemoteAddr().String())
		if err != nil || host != tc.wantHost || port != tc.wantPort {
			t.Errorf("%q: RemoteAddr=%q split=(%q,%q,%v), want (%q,%q)", tc.hdr, c.RemoteAddr(), host, port, err, tc.wantHost, tc.wantPort)
		}
	}
}
