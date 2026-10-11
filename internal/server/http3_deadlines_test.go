package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

func h3FreePort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 50; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		port := ln.Addr().(*net.TCPAddr).Port
		pc, err := net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(port))
		ln.Close()
		if err == nil {
			pc.Close()
			return port
		}
	}
	t.Fatal("no free tcp+udp port")
	return 0
}

// F15000: the HTTP/3 listener had neither the read limit nor the write limit
// http.Server enforces on TCP, so a client that stalled its request body or
// stopped reading the response pinned the handler indefinitely. Each case below
// is also cut on the TCP listener (the control in the proof).
func TestHTTP3EnforcesReadAndWriteTimeouts(t *testing.T) {
	_, _, cert := ccrCert(t, nil, nil, false, 11, x509.ExtKeyUsageServerAuth, "up.test", "big.test", "sse.test")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			for i := 0; i < 12; i++ {
				fmt.Fprint(w, "tick\n")
				w.(http.Flusher).Flush()
				time.Sleep(200 * time.Millisecond)
			}
			return
		}
		io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, "done")
	}))
	defer origin.Close()

	root := t.TempDir()
	big := make([]byte, 48<<20)
	rand.New(rand.NewSource(1)).Read(big)
	if err := os.WriteFile(filepath.Join(root, "big.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}

	port := h3FreePort(t)
	proxy := func(host string) config.Domain {
		return config.Domain{Host: host, Type: "proxy", SSL: config.SSLConfig{Mode: "manual"},
			Proxy: config.ProxyConfig{Upstreams: []config.Upstream{{Address: origin.URL, Weight: 1}}}}
	}
	cfg := &config.Config{
		Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text",
			HTTPSListen: "127.0.0.1:" + strconv.Itoa(port), HTTP3Enabled: true},
		Domains: []config.Domain{
			proxy("up.test"), proxy("sse.test"),
			{Host: "big.test", Type: "static", Root: root, SSL: config.SSLConfig{Mode: "manual"}},
		},
	}
	cfg.Global.Timeouts.Read.Duration = time.Second
	cfg.Global.Timeouts.ReadHeader.Duration = time.Second
	cfg.Global.Timeouts.Write.Duration = time.Second
	s := New(cfg, logger.New("error", "text"))
	t.Cleanup(func() { s.cancel() })
	for _, h := range []string{"up.test", "big.test", "sse.test"} {
		s.tlsMgr.RegisterCert(h, &cert)
	}
	if err := s.startHTTP3(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.h3srv.Close() })
	time.Sleep(300 * time.Millisecond)

	url := "https://127.0.0.1:" + strconv.Itoa(port)
	h3For := func(sni string) (*http.Client, func()) {
		rt := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: sni}}
		return &http.Client{Transport: rt}, func() { rt.Close() }
	}

	t.Run("stalled request body is cut", func(t *testing.T) {
		c, done := h3For("up.test")
		defer done()
		pr, pw := io.Pipe()
		go func() {
			pw.Write([]byte("a"))
			time.Sleep(2500 * time.Millisecond)
			pw.Write([]byte("b"))
			pw.Close()
		}()
		req, _ := http.NewRequest("POST", url+"/", pr)
		req.Host = "up.test"
		resp, err := c.Do(req)
		if err != nil {
			return // cut: acceptable
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == 200 && string(b) == "done" {
			t.Errorf("a request body stalled for 2.5s completed over HTTP/3 with global.timeouts.read=1s")
		}
	})

	t.Run("client that stops reading is cut", func(t *testing.T) {
		c, done := h3For("big.test")
		defer done()
		req, _ := http.NewRequest("GET", url+"/big.bin", nil)
		req.Host = "big.test"
		resp, err := c.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		time.Sleep(3 * time.Second)
		n, err := io.Copy(io.Discard, resp.Body)
		if err == nil && n == int64(len(big)) {
			t.Errorf("a response the client left unread for 3s was delivered whole over HTTP/3 with global.timeouts.write=1s")
		}
	})

	t.Run("a response that keeps progressing is not cut", func(t *testing.T) {
		c, done := h3For("sse.test")
		defer done()
		req, _ := http.NewRequest("GET", url+"/stream", nil)
		req.Host = "sse.test"
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil || len(b) != 12*len("tick\n") {
			t.Errorf("stream longer than global.timeouts.read was cut: %d bytes, err=%v", len(b), err)
		}
	})
}
