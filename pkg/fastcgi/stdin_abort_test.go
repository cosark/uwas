package fastcgi

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"
)

// A body reader that fails mid-stream (MaxBytesReader limit, client abort)
// must not be terminated with an empty FCGI_STDIN record: that record tells
// the application the body is complete, so a truncated POST would be
// processed as if it were whole. The connection must be dropped instead.
func TestExecuteStdinErrorDoesNotTerminateStdin(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		sawEmptyStdin bool
		stdinBytes    int
	}
	done := make(chan result, 1)
	go func() {
		var res result
		defer func() { done <- res }()
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(c)
		for {
			rec, err := ReadRecord(br)
			if err != nil {
				return
			}
			if rec.Type == TypeStdin {
				if rec.ContentLength == 0 {
					res.sawEmptyStdin = true
					return
				}
				res.stdinBytes += int(rec.ContentLength)
			}
		}
	}()

	client := NewClient(PoolConfig{Address: "tcp:" + ln.Addr().String(), MaxIdle: 1, MaxOpen: 1})
	defer client.Close()

	_, err = client.Execute(context.Background(), map[string]string{
		"SCRIPT_FILENAME": "/t.php", "REQUEST_METHOD": "POST",
	}, &errReader{data: make([]byte, 200000), failAt: 100000})
	if err == nil {
		t.Fatal("expected error from failing stdin reader")
	}
	res := <-done
	if res.sawEmptyStdin {
		t.Fatal("empty FCGI_STDIN terminator sent after a body read error: truncated POST looks complete")
	}
}
