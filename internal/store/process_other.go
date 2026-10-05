//go:build !unix && !windows

package store

import "os"

// processAlive is the best-effort fallback for platforms this project does
// not ship on (Plan 9, js/wasm). os.FindProcess cannot distinguish a dead
// process there, so it errs toward "alive": a stale lock may need the
// operator to remove <dir>/LOCK. macOS, Linux and Windows - the supported
// targets - have their own, accurate implementations.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := os.FindProcess(pid)
	return err == nil
}
