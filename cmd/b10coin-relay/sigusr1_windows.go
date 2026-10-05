//go:build windows

package main

import "os"

// notifyStatsSignal is a no-op on Windows: SIGUSR1 does not exist there. The
// 60-second timer still surfaces the counters, which is the whole of N-9's
// requirement that a relay cannot look healthy by being silent while it
// drops.
func notifyStatsSignal(ch chan<- os.Signal) {}
