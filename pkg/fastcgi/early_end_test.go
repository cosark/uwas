package fastcgi

import (
	"bufio"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// An application that answers (e.g. 413/early exit) and stops reading STDIN
// must not leave Execute blocked writing a large body until the deadline.
func TestExecuteEarlyEndRequestDoesNotBlockOnBody(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	release := make(chan struct{})
	defer close(release)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		for { // read through end of PARAMS only
			rec, err := ReadRecord(br)
			if err != nil {
				return
			}
			if rec.Type == TypeParams && rec.ContentLength == 0 {
				break
			}
		}
		bw := bufio.NewWriter(c)
		WriteRecord(bw, TypeStdout, 1, []byte("Status: 413 Payload Too Large\r\n\r\nno"))
		end := make([]byte, 8)
		binary.BigEndian.PutUint32(end, 0)
		WriteRecord(bw, TypeEndRequest, 1, end)
		bw.Flush()
		<-release // stop reading stdin
	}()

	client := NewClient(PoolConfig{Address: "tcp:" + ln.Addr().String(), MaxIdle: 1, MaxOpen: 1})
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	resp, err := client.Execute(ctx, map[string]string{"SCRIPT_FILENAME": "/t.php"},
		strings.NewReader(strings.Repeat("x", 64<<20)))
	if time.Since(start) > 5*time.Second {
		t.Fatalf("Execute blocked %v writing body to an app that already ended the request (err=%v)", time.Since(start), err)
	}
	if err != nil || resp == nil || !strings.Contains(string(resp.Stdout()), "413") {
		t.Fatalf("want the early response, got resp=%v err=%v", resp, err)
	}
}
