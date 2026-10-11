package wordpress

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// F9200: Harden runs as root and creates, writes and removes the XML-RPC
// mu-plugin under wp-content/mu-plugins. A wp-content or mu-plugins symlink the
// domain user planted must not redirect those operations outside the web root.
func TestHardenXMLRPCDoesNotFollowPlantedSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX symlinks")
	}
	cfg := []byte("<?php\nrequire_once ABSPATH . 'wp-settings.php';\n")
	site := func(t *testing.T) string {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "wp-content"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "wp-config.php"), cfg, 0o600); err != nil {
			t.Fatal(err)
		}
		return root
	}
	yes, no := true, false

	t.Run("control: real directory is written", func(t *testing.T) {
		root := site(t)
		if _, err := Harden(root, HardenOptions{DisableXMLRPC: &yes}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(root, "wp-content", "mu-plugins", "uwas-security.php")); err != nil {
			t.Fatalf("mu-plugin not written: %v", err)
		}
	})

	t.Run("mu-plugins symlink: write", func(t *testing.T) {
		root, out := site(t), t.TempDir()
		os.Symlink(out, filepath.Join(root, "wp-content", "mu-plugins"))
		if _, err := Harden(root, HardenOptions{DisableXMLRPC: &yes}); err == nil {
			t.Error("Harden succeeded through a mu-plugins symlink, want an error")
		}
		if _, err := os.Stat(filepath.Join(out, "uwas-security.php")); err == nil {
			t.Error("mu-plugin was written outside the web root")
		}
	})

	t.Run("wp-content symlink: no directory created outside", func(t *testing.T) {
		root, out := t.TempDir(), t.TempDir()
		os.Symlink(out, filepath.Join(root, "wp-content"))
		os.WriteFile(filepath.Join(root, "wp-config.php"), cfg, 0o600)
		Harden(root, HardenOptions{DisableXMLRPC: &yes})
		if _, err := os.Stat(filepath.Join(out, "mu-plugins")); err == nil {
			t.Error("mu-plugins directory was created outside the web root")
		}
	})

	t.Run("mu-plugins symlink: remove", func(t *testing.T) {
		root, out := site(t), t.TempDir()
		victim := filepath.Join(out, "uwas-security.php")
		os.WriteFile(victim, []byte("KEEP"), 0o644)
		os.Symlink(out, filepath.Join(root, "wp-content", "mu-plugins"))
		Harden(root, HardenOptions{DisableXMLRPC: &no})
		if _, err := os.Stat(victim); err != nil {
			t.Error("a file outside the web root was removed through the mu-plugins symlink")
		}
	})
}
