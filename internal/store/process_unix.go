//go:build unix

package store

import (
	"errors"
	"os"
	"syscall"
)

// processAlive reports whether pid names a live process. Signal 0 performs
// the kernel's permission and existence check without delivering anything:
// nil means the process exists, EPERM means it exists but belongs to another
// user (still alive), and ESRCH (surfaced by os as ErrProcessDone) means it
// does not. pid <= 0 is refused because kill(0, ...) targets a whole process
// group.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	if errors.Is(err, os.ErrProcessDone) {
		return false
	}
	return errors.Is(err, syscall.EPERM)
}
