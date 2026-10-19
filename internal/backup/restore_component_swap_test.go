package backup

// RestoreBackup validated containment (safeRestorePath) before the parent
// directories of an entry existed, so not-yet-existing path components were
// checked only as a missing suffix. A writer with access to the restore root
// (a web root is tenant file space) could swap one of those components for a
// symlink between validation and creation; MkdirAll follows it and the
// restored file lands outside the web root. The extraction loop now re-runs
// the containment check after directory creation, when every component
// resolves for real. These tests gate that window deterministically through
// the osMkdirAllFn seam: the swap fires the moment the directory exists, and
// the escaped entry must be skipped while an unaffected sibling entry still
// restores inside the root.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

type swapProvider struct {
	name    string
	archive []byte
}

func (p *swapProvider) Name() string { return p.name }
func (p *swapProvider) Upload(_ context.Context, _ string, _ io.Reader) error {
	return nil
}
func (p *swapProvider) Download(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(p.archive)), nil
}
func (p *swapProvider) List(_ context.Context) ([]BackupInfo, error) { return nil, nil }
func (p *swapProvider) Delete(_ context.Context, _ string) error     { return nil }

func swapArchive(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	write := func(name, body string) {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	write("sites/blog/uploads/f", "RESTORED-PAYLOAD") // gated swap target
	write("sites/plain/f", "CONTROL-PAYLOAD")         // unaffected control
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func swapStubs(escapeDir string, shellCmds *[]string) (restore func()) {
	orig := osMkdirAllFn
	swapped := false
	osMkdirAllFn = func(path string, perm os.FileMode) error {
		err := orig(path, perm)
		// The file's parent chain is webRoot/blog/uploads; once MkdirAll has
		// created both components (still empty), swap blog for a symlink to
		// the escape directory and recreate the leaf inside it, so the
		// extraction proceeds through the link.
		if err == nil && !swapped && strings.HasSuffix(filepath.ToSlash(path), "/blog/uploads") {
			swapped = true
			blog := filepath.Dir(path)
			if rmErr := os.Remove(path); rmErr == nil {
				if rmErr := os.Remove(blog); rmErr == nil {
					if err := os.Symlink(escapeDir, blog); err == nil {
						_ = os.MkdirAll(blog+"/uploads", perm)
					}
				}
			}
		}
		return err
	}
	return func() { osMkdirAllFn = orig }
}

func TestRestoreBackupComponentSwapSkipped(t *testing.T) {
	webRoot := t.TempDir()
	escapeDir := t.TempDir()

	m := New(config.BackupConfig{}, logger.New("error", "text"))
	m.providers = map[string]StorageProvider{
		"stub": &swapProvider{name: "stub", archive: swapArchive(t)},
	}
	m.webRoot = webRoot
	m.configPath = filepath.Join(t.TempDir(), "uwas.yaml")

	restore := swapStubs(escapeDir, &[]string{})
	defer restore()

	if err := m.RestoreBackup("swap.tar.gz", "stub"); err != nil {
		t.Fatalf("restore errored: %v", err)
	}

	escaped := filepath.Join(escapeDir, "uploads", "f")
	if _, statErr := os.Lstat(escaped); statErr == nil {
		t.Fatalf("restored file escaped the restore root: %s exists outside %s", escaped, webRoot)
	}
	// The unaffected control must still restore inside the web root.
	control := filepath.Join(webRoot, "plain", "f")
	body, readErr := os.ReadFile(control)
	if readErr != nil || string(body) != "CONTROL-PAYLOAD" {
		t.Fatalf("control entry not restored in-root: %v", readErr)
	}
}
