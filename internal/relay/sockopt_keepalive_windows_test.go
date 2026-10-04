//go:build windows

// Windows half of the keepalive introspection (see the unix file): the check
// is the same SO_KEEPALIVE read-back, with the two Windows differences only -
// the raw fd is a syscall.Handle, and that is Go's own syscall surface, no
// new dependency - so the property is TESTED on Windows, never skipped and
// never weakened to a config read.
package relay

import (
	"fmt"
	"syscall"
)

// sockoptKeepaliveOn is the Windows counterpart of the unix helper: it reads
// SO_KEEPALIVE back from the accepted connection's raw socket.
func sockoptKeepaliveOn(raw syscall.RawConn) error {
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		// SO_KEEPALIVE enabled reads back non-zero (1 on Windows), disabled
		// reads 0 - assert non-zero, never "equals 1", to match the unix
		// helper's tolerance of stacks that answer with a probe count.
		on, err := syscall.GetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
		if err != nil {
			sockErr = err
		} else if on == 0 {
			sockErr = fmt.Errorf("SO_KEEPALIVE = 0 (off) - a half-open connection would keep its slot forever")
		}
	}); err != nil {
		sockErr = err
	}
	return sockErr
}
