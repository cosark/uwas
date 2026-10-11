package admin

import (
	"runtime"
	"sync"
)

var (
	goroutineDumpMu  sync.Mutex
	goroutineDumpBuf = make([]byte, 1<<20)
)

// allGoroutineStacks returns the stack of every goroutine in the process. The
// buffer grows until the whole dump fits. A fixed buffer cuts the dump short
// once enough goroutines from earlier tests are still running (every New starts
// workers that are never stopped), and a test that waits for a goroutine in the
// missing part never sees it: it spins until the package times out, or fails
// with "never reached". The buffer is kept between calls because the callers
// poll in a loop.
func allGoroutineStacks() string {
	goroutineDumpMu.Lock()
	defer goroutineDumpMu.Unlock()
	for {
		n := runtime.Stack(goroutineDumpBuf, true)
		if n < len(goroutineDumpBuf) {
			return string(goroutineDumpBuf[:n])
		}
		goroutineDumpBuf = make([]byte, 2*len(goroutineDumpBuf))
	}
}
