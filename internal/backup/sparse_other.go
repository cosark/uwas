//go:build !unix

package backup

import "os"

// allocatedBytes is unknown here, so no file is treated as sparse.
func allocatedBytes(os.FileInfo) (int64, bool) { return 0, false }
