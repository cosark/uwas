package backup

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

// F9810: the upload (and the S3 client) used to be capped at a fixed 5 minutes
// counted from before the archive was built, so a large backup failed even
// while it kept moving. The limit is now an idle limit on the transfer.

func writeRandomEntry(tw *tar.Writer, name string, size int) error {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(size), Mode: 0o644}); err != nil {
		return err
	}
	_, err := tw.Write(buf)
	return err
}

type funcProvider struct {
	upload func(ctx context.Context, name string, data io.Reader) error
}

func (p *funcProvider) Name() string { return "func" }
func (p *funcProvider) Upload(ctx context.Context, name string, data io.Reader) error {
	return p.upload(ctx, name, data)
}
func (p *funcProvider) Download(context.Context, string) (io.ReadCloser, error) {
	return nil, os.ErrNotExist
}
func (p *funcProvider) List(context.Context) ([]BackupInfo, error) { return nil, nil }
func (p *funcProvider) Delete(context.Context, string) error       { return nil }

func withIdleTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := opIdleTimeout
	opIdleTimeout = d
	t.Cleanup(func() { opIdleTimeout = old })
}

func TestUploadOutlivesIdleTimeoutWhileProgressing(t *testing.T) {
	withIdleTimeout(t, 400*time.Millisecond)

	var reads int
	var ctxErr error
	p := &funcProvider{upload: func(ctx context.Context, _ string, data io.Reader) error {
		buf := make([]byte, 4096)
		start := time.Now()
		for {
			n, err := data.Read(buf)
			if n > 0 {
				reads++
				time.Sleep(150 * time.Millisecond) // steady, slower than idle/2
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
		}
		if time.Since(start) <= opIdleTimeout {
			t.Errorf("transfer finished in %v, not longer than the idle timeout: test did not exercise it", time.Since(start))
		}
		ctxErr = ctx.Err()
		return nil
	}}
	_, err := archiveAndUpload(context.Background(), p, "idle-*.tar.gz", "x.tar.gz", func(tw *tar.Writer) error {
		return writeRandomEntry(tw, "data.bin", 40*1024)
	})
	if err != nil {
		t.Fatalf("progressing upload was cut off: %v", err)
	}
	if ctxErr != nil {
		t.Fatalf("upload context ended while bytes were still moving: %v", ctxErr)
	}
	if reads < 5 {
		t.Fatalf("only %d reads, too few to span the idle timeout", reads)
	}
}

func TestUploadAbandonedWhenStalled(t *testing.T) {
	withIdleTimeout(t, 200*time.Millisecond)

	got := make(chan error, 1)
	p := &funcProvider{upload: func(ctx context.Context, _ string, data io.Reader) error {
		buf := make([]byte, 1024)
		if _, err := data.Read(buf); err != nil {
			return err
		}
		select { // stall: never read again
		case <-ctx.Done():
			got <- ctx.Err()
			return ctx.Err()
		case <-time.After(10 * time.Second):
			got <- nil
			return nil
		}
	}}
	_, err := archiveAndUpload(context.Background(), p, "stall-*.tar.gz", "x.tar.gz", func(tw *tar.Writer) error {
		return writeRandomEntry(tw, "data.bin", 16*1024)
	})
	if err == nil {
		t.Fatal("stalled upload was not abandoned")
	}
	if e := <-got; e != context.Canceled {
		t.Fatalf("upload context error = %v, want context.Canceled from the idle timer", e)
	}
}

// The S3 provider sizes its body from the backing file; wrapping the file for
// progress tracking must not turn the PUT into a chunked upload (real S3
// rejects those with 501 MissingContentLength).
func TestS3UploadKeepsContentLengthThroughProgressReader(t *testing.T) {
	var mu sync.Mutex
	var cl int64
	var te []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cl, te = r.ContentLength, r.TransferEncoding
		mu.Unlock()
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := NewS3Provider(srv.URL, "bkt", "ak", "sk", "us-east-1")
	size, err := archiveAndUpload(context.Background(), p, "s3-*.tar.gz", "uwas-backup-x.tar.gz", func(tw *tar.Writer) error {
		return writeRandomEntry(tw, "data.bin", 8*1024)
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if cl != size {
		t.Fatalf("Content-Length = %d, want archive size %d (transfer-encoding %v)", cl, size, te)
	}
	if len(te) != 0 {
		t.Fatalf("upload was chunked: %v", te)
	}
}
