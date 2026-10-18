//go:build !unix

package main

import "time"

// The benchmarks leave the CPU figure out here; everything else runs as on
// Unix.
const haveCPUTime = false

func cpuTime() time.Duration { return 0 }
