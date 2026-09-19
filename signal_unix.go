//go:build unix

package main

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var signalOnce sync.Once

// watchSignals dumps the full state (summary + every open connection) to the
// log on SIGUSR1: `kill -USR1 <pid>`.
func watchSignals(s *Server) {
	signalOnce.Do(func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGUSR1)
		go func() {
			for range ch {
				s.stats.Dump(s.runtime.Load())
			}
		}()
	})
}
