//go:build windows

package store

import "os"

// processAlive reports whether pid names a live process. On Windows
// os.FindProcess opens the process and fails when it does not exist, which is
// exactly the existence check needed; the handle is released immediately.
// pid <= 0 is refused for symmetry with the Unix path (there is no process 0
// to own a data directory).
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	_ = p.Release()
	return true
}
