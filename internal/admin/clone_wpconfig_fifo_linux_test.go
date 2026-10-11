//go:build linux

package admin

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/migrate"
)

// A FIFO named wp-config.php inside the docroot must be refused, not opened
// (opening a FIFO with no writer blocks forever).
func TestDetectWordPressDBRefusesFIFO(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "wp-config.php"), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	req := &migrate.CloneRequest{SourceRoot: root}
	go func() { done <- detectWordPressDB(req) }()
	select {
	case err := <-done:
		if err == nil || req.SourceDB != "" {
			t.Fatalf("FIFO: err=%v req=%+v, want refusal", err, req)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("detectWordPressDB blocked on a FIFO wp-config.php")
	}
}
