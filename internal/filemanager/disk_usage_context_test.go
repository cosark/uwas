package filemanager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// F14901: DiskUsageContext agrees with DiskUsage on a live context and stops
// at once on a cancelled one.
func TestDiskUsageContextStopsWhenCancelled(t *testing.T) {
	dir := t.TempDir()
	for d := 0; d < 5; d++ {
		sub := filepath.Join(dir, fmt.Sprintf("d%d", d))
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		for f := 0; f < 20; f++ {
			if err := os.WriteFile(filepath.Join(sub, fmt.Sprintf("f%d", f)), []byte("0123456789"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	want, err := DiskUsage(dir)
	if err != nil || want != 5*20*10 {
		t.Fatalf("control DiskUsage = %d, %v; want 1000", want, err)
	}
	got, err := DiskUsageContext(context.Background(), dir)
	if err != nil || got != want {
		t.Errorf("live context: %d, %v; want %d", got, err, want)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if n, err := DiskUsageContext(ctx, dir); !errors.Is(err, context.Canceled) || n != 0 {
		t.Errorf("cancelled context: %d, %v; want 0, context.Canceled", n, err)
	}
}
