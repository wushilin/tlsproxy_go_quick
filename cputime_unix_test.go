//go:build unix

package main

import (
	"syscall"
	"time"
)

// haveCPUTime: the benchmarks can report the CPU they cost.
const haveCPUTime = true

// cpuTime is the CPU this process has used, for the benchmarks.
func cpuTime() time.Duration {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}
