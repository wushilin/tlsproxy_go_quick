package main

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

var (
	logMu  sync.Mutex
	logOut io.Writer = os.Stderr
)

// logf writes one timestamped (UTC, milliseconds) line to stderr.
func logf(format string, args ...any) {
	ts := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	logMu.Lock()
	fmt.Fprintf(logOut, ts+" "+format+"\n", args...)
	logMu.Unlock()
}

// humanBytes formats a byte count like "6.54 KiB".
func humanBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	v, u := float64(n), 0
	for v >= 1024 && u < len(units)-1 {
		v /= 1024
		u++
	}
	return fmt.Sprintf("%.2f %s", v, units[u])
}

// humanDuration formats like "42ms", "2.50s", "1h02m03s".
func humanDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
	s := int64(d.Seconds())
	h, m, s := s/3600, s/60%60, s%60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	return fmt.Sprintf("%dm%02ds", m, s)
}
