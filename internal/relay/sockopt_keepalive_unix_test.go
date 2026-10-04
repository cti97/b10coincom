//go:build unix

// The one test-only socket introspection in the suite, kept to a single
// helper behind a build constraint so every test file stays compilable on
// every target (Task 9): TCP keepalive state cannot be read back through the
// portable net API - Go exposes only SetKeepAlive*, never a getter - so the
// assertion that "the accepted socket really carries SO_KEEPALIVE" has to ask
// the kernel. The question is identical on every OS; only the fd type differs
// (int on Unix, syscall.Handle on Windows - see sockopt_keepalive_windows_test.go).
// On both sides the property is TESTED, never skipped.
package relay

import (
	"fmt"
	"syscall"
)

// sockoptKeepaliveOn reads SO_KEEPALIVE back from an accepted connection's
// raw socket and reports an error when the flag is off (or unreadable).
func sockoptKeepaliveOn(raw syscall.RawConn) error {
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		// Enabled keepalive reads back non-zero (1 on Linux and Windows;
		// the BSD stacks of darwin answer 8), disabled reads 0 - assert
		// non-zero, never "equals 1", or the darwin hosts would fail a
		// correct relay.
		on, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
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
