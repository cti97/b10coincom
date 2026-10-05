//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// notifyStatsSignal registers SIGUSR1 on the channel, so an operator can make
// the relay print one counters line on demand (audit N-9) - "kill -USR1
// $(pidof b10coin-relay)" - without waiting out the 60-second timer or
// restarting the process. SIGUSR1 is POSIX-only, so the Windows build supplies
// a no-op instead and relies on the timer.
func notifyStatsSignal(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGUSR1)
}
