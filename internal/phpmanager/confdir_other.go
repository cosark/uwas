//go:build !unix

package phpmanager

// secureConfDir has no ownership model to check outside unix.
func secureConfDir(dir string) error { return nil }
