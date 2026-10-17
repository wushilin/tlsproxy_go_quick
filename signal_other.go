//go:build !unix

package main

import (
	"os"
	"os/signal"
	"sync"
)

var signalOnce sync.Once

// Windows has no SIGUSR1 dump, but Ctrl+C still flushes buffered logs.
func watchSignals(s *Server) {
	signalOnce.Do(func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt)
		go func() {
			sig := <-stop
			logf("stopping: received %s", sig)
			FlushLogs()
			os.Exit(0)
		}()
	})
}
