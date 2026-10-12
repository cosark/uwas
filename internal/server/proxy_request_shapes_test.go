package server

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

type upstreamSeen struct {
	mu   sync.Mutex
	reqs []*http.Request
	body []string
}

func (u *upstreamSeen) last() (*http.Request, string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.reqs) == 0 {
		return nil, ""
	}
	return u.reqs[len(u.reqs)-1], u.body[len(u.body)-1]
}

// Characterization (F18201): what a domain proxy forwards for hostile request
// shapes, driven over a real socket so net/http's own parsing is in the path.
// The upstream sees no smuggling shape (CL+TE together, duplicate CL), no
// client-chosen forwarding identity and no header named by Connection.
func TestDomainProxyForwardsNoSpoofedOrSmuggledShapes(t *testing.T) {
	seen := &upstreamSeen{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen.mu.Lock()
		seen.reqs = append(seen.reqs, r)
		seen.body = append(seen.body, string(b))
		seen.mu.Unlock()
		fmt.Fprint(w, "ok")
	}))
	defer up.Close()

	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text"},
		Domains: []config.Domain{{
			Host: "px.test", Type: "proxy", Root: t.TempDir(), SSL: config.SSLConfig{Mode: "off"},
			Proxy: config.ProxyConfig{Upstreams: []config.Upstream{{Address: up.URL, Weight: 1}}, AllowPrivateUpstreams: true},
		}},
	}
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel(); time.Sleep(50 * time.Millisecond) })
	s.handler = s.buildMiddlewareChain()
	front := httptest.NewServer(s.handler)
	defer front.Close()

	raw := func(req string) (string, error) {
		c, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
		if err != nil {
			return "", err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte(req)); err != nil {
			return "", err
		}
		line, _ := bufio.NewReader(c).ReadString('\n')
		return strings.TrimSpace(line), nil
	}

	t.Run("spoofed forwarding headers", func(t *testing.T) {
		_, err := raw("GET /p HTTP/1.1\r\nHost: px.test\r\nUser-Agent: t\r\n" +
			"X-Forwarded-For: 6.6.6.6\r\nX-Real-IP: 6.6.6.6\r\nForwarded: for=6.6.6.6;proto=https\r\n" +
			"X-Forwarded-Host: evil.test\r\nX-Forwarded-Proto: https\r\n" +
			"Connection: close, X-Secret\r\nX-Secret: hunter2\r\n\r\n")
		if err != nil {
			t.Fatal(err)
		}
		r, _ := seen.last()
		if r == nil {
			t.Fatal("upstream saw nothing")
		}
		if got := r.Header.Values("X-Forwarded-For"); len(got) != 1 || strings.Contains(got[0], "6.6.6.6") {
			t.Errorf("X-Forwarded-For = %q", got)
		}
		if r.Header.Get("X-Real-IP") == "6.6.6.6" {
			t.Errorf("X-Real-IP kept the client's value")
		}
		if r.Header.Get("Forwarded") != "" {
			t.Errorf("Forwarded passed through: %q", r.Header.Get("Forwarded"))
		}
		if r.Header.Get("X-Forwarded-Host") != "px.test" {
			t.Errorf("X-Forwarded-Host = %q", r.Header.Get("X-Forwarded-Host"))
		}
		if r.Header.Get("X-Forwarded-Proto") != "http" {
			t.Errorf("X-Forwarded-Proto = %q", r.Header.Get("X-Forwarded-Proto"))
		}
		if r.Header.Get("X-Secret") != "" {
			t.Errorf("a header named by Connection was forwarded")
		}
	})

	shapes := map[string]string{
		"CL+TE":        "POST /s HTTP/1.1\r\nHost: px.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
		"dup CL":       "POST /s HTTP/1.1\r\nHost: px.test\r\nContent-Length: 4\r\nContent-Length: 5\r\nConnection: close\r\n\r\nabcde",
		"TE obfuscate": "POST /s HTTP/1.1\r\nHost: px.test\r\nTransfer-Encoding: xchunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
		"TE space":     "POST /s HTTP/1.1\r\nHost: px.test\r\nTransfer-Encoding : chunked\r\nContent-Length: 4\r\nConnection: close\r\n\r\n0\r\n\r\n",
	}
	for name, req := range shapes {
		name, req := name, req
		t.Run(name, func(t *testing.T) {
			seen.mu.Lock()
			n := len(seen.reqs)
			seen.mu.Unlock()
			status, err := raw(req)
			if err != nil {
				t.Fatal(err)
			}
			seen.mu.Lock()
			after := seen.reqs[n:]
			bodies := seen.body[n:]
			seen.mu.Unlock()
			for i, r := range after {
				if len(r.TransferEncoding) > 0 && r.ContentLength >= 0 {
					t.Errorf("upstream got both Transfer-Encoding %v and Content-Length %d", r.TransferEncoding, r.ContentLength)
				}
				if bodies[i] != "" && name != "CL+TE" {
					t.Errorf("%s: upstream was given body %q (status %q)", name, bodies[i], status)
				}
			}
			t.Logf("%s: front status %q, upstream requests %d", name, status, len(after))
		})
	}
}
