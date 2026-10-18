//go:build !linux

package main

// Only Linux can splice(2) socket to socket; elsewhere every direction is
// copied through a pooled buffer.
func newSpliceMover(from, to duplex, size int) mover { return nil }
