package wordpress

// F5000: the UpdateCore download fallback had no size cap (the installer has 100MB).

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
)

type zeroReader struct{ n int64 }

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > z.n {
		p = p[:z.n]
	}
	for i := range p {
		p[i] = 0
	}
	z.n -= int64(len(p))
	return len(p), nil
}

func f5000run(t *testing.T, size int64) int64 {
	oldGet, oldLook, oldExec := httpGetFn, execLookPathFn, execCommandFn
	t.Cleanup(func() { httpGetFn, execLookPathFn, execCommandFn = oldGet, oldLook, oldExec })
	execLookPathFn = func(string) (string, error) { return "", exec.ErrNotFound }
	httpGetFn = func(url string) (*http.Response, error) {
		if strings.HasSuffix(url, ".sha1") {
			return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(&zeroReader{n: size})}, nil
	}
	var seen int64 = -1
	execCommandFn = func(name string, args ...string) *exec.Cmd {
		if name == "tar" && len(args) >= 2 {
			if fi, err := os.Stat(args[1]); err == nil {
				seen = fi.Size()
			}
		}
		return exec.Command("false")
	}
	UpdateCore(t.TempDir())
	return seen
}

func TestUpdateCoreCapsDownloadSize(t *testing.T) {
	const cap = 100 << 20
	if got := f5000run(t, 1<<20); got != 1<<20 {
		t.Fatalf("invalid proof: control stored %d, want %d", got, 1<<20)
	}
	got := f5000run(t, cap+(20<<20))
	if got != -1 {
		t.Errorf("oversized download reached extraction (%d bytes), want rejection at %d bytes (F5000)", got, cap)
	}
}
