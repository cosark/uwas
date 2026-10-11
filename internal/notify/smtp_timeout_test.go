package notify

import (
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeSMTP speaks just enough SMTP to accept one message; it reports the DATA
// section it received.
func fakeSMTP(t *testing.T) (port int, delivered <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				fmt.Fprint(c, "220 fake ESMTP\r\n")
				buf := make([]byte, 4096)
				var data strings.Builder
				inData := false
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					chunk := string(buf[:n])
					if inData {
						data.WriteString(chunk)
						if strings.Contains(data.String(), "\r\n.\r\n") {
							fmt.Fprint(c, "250 ok\r\n")
							got <- data.String()
							inData = false
						}
						continue
					}
					for _, line := range strings.Split(strings.TrimSpace(chunk), "\r\n") {
						switch {
						case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
							fmt.Fprint(c, "250 fake\r\n")
						case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
							fmt.Fprint(c, "250 ok\r\n")
						case strings.HasPrefix(line, "DATA"):
							fmt.Fprint(c, "354 go\r\n")
							inData = true
						case strings.HasPrefix(line, "QUIT"):
							fmt.Fprint(c, "221 bye\r\n")
							return
						}
					}
				}
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, got
}

// F13600: smtp.SendMail has no deadline, so an SMTP server that accepts the
// connection and never answers pinned the alerting goroutine forever.
func TestSendEmailTimesOutOnSilentServer(t *testing.T) {
	origCheck, origTimeout := notifyHostSafetyCheck, smtpTimeout
	notifyHostSafetyCheck = func(string) error { return nil }
	smtpTimeout = 300 * time.Millisecond
	t.Cleanup(func() { notifyHostSafetyCheck, smtpTimeout = origCheck, origTimeout })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(io.Discard, c) }()
		}
	}()
	cfg := map[string]string{
		"smtp_host": "127.0.0.1", "smtp_port": fmt.Sprint(ln.Addr().(*net.TCPAddr).Port),
		"to": "a@example.com", "from": "u@example.com",
	}

	before := runtime.NumGoroutine()
	done := make(chan error, 1)
	go func() { done <- sendEmail(cfg, testMsg()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("silent SMTP server: want an error, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sendEmail still blocked against a silent SMTP server")
	}
	// The goroutines serving the connection (ours and the fake's) must wind
	// down, not accumulate.
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before+2 {
		t.Errorf("goroutines grew from %d to %d after a timed-out send", before, n)
	}
}

// Control: the bounded sender still delivers to a responsive server and
// rejects CR/LF smuggled into the envelope like smtp.SendMail does.
func TestSendMailBoundedDeliversAndRejectsCRLF(t *testing.T) {
	port, delivered := fakeSMTP(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	if err := sendMailBounded(addr, nil, "u@example.com", []string{"a@example.com", "b@example.com"}, []byte("Subject: x\r\n\r\nhello")); err != nil {
		t.Fatalf("responsive server: %v", err)
	}
	select {
	case d := <-delivered:
		if !strings.Contains(d, "hello") {
			t.Errorf("delivered data = %q", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("message never reached the server")
	}

	if err := sendMailBounded(addr, nil, "u@example.com\r\nRCPT TO:<x@evil>", []string{"a@example.com"}, []byte("x")); err == nil {
		t.Error("CR/LF in the sender was accepted")
	}
	if err := sendMailBounded(addr, nil, "u@example.com", []string{"a@example.com\nRCPT TO:<x@evil>"}, []byte("x")); err == nil {
		t.Error("CR/LF in a recipient was accepted")
	}
	if err := sendMailBounded(addr, nil, "u@example.com", nil, []byte("x")); err == nil {
		t.Error("no recipients accepted")
	}
}
