package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Two streams, like a daemon's stdout and stderr: normal activity (logf) and
// problems (errorf). Each goes to the process's own stdout/stderr or, when
// [logging] names a file for it, to a rotating file (see rotate.go).
var (
	logMu   sync.Mutex
	logOut  io.Writer = os.Stdout // where logf goes without a file (tests swap it)
	logErr  io.Writer = os.Stderr
	sinkCfg *LogConfig
	sinkOut *FileLogger
	sinkErr *FileLogger
)

// ConfigureLogging applies the [logging] settings (at startup and on every
// config reload). On error the previous destinations stay in use.
func ConfigureLogging(cfg LogConfig) error {
	logMu.Lock()
	defer logMu.Unlock()
	if sinkCfg != nil && *sinkCfg == cfg {
		return nil
	}
	var out, errl *FileLogger
	var err error
	if cfg.Stdout != "" {
		if out, err = OpenFileLogger(cfg.Stdout, cfg); err != nil {
			return fmt.Errorf("cannot open log file %s: %w", cfg.Stdout, err)
		}
	}
	switch {
	case cfg.Stderr == "":
	case cfg.Stderr == cfg.Stdout:
		errl = out // both streams share one file
	default:
		if errl, err = OpenFileLogger(cfg.Stderr, cfg); err != nil {
			if out != nil {
				out.Close()
			}
			return fmt.Errorf("cannot open log file %s: %w", cfg.Stderr, err)
		}
	}
	oldOut, oldErr := sinkOut, sinkErr
	sinkCfg, sinkOut, sinkErr = &cfg, out, errl
	// A reload may redirect either stream. Do this after publishing the new
	// sinks, and only once when stdout and stderr shared one logger. Close also
	// waits for background compression: a replacement using the same path must
	// not rotate the generations while the old logger is still compressing one.
	if oldOut != nil {
		oldOut.Close()
	}
	if oldErr != nil && oldErr != oldOut {
		oldErr.Close()
	}
	return nil
}

// recentLog keeps the last lines of both streams for the web console.
const recentLogSize = 2000

var (
	recentLines [recentLogSize]string
	recentNext  int // total lines ever stored; index = recentNext % size
)

// RecentLog returns up to n of the newest lines (oldest first) that contain
// filter ("" = all).
func RecentLog(n int, filter string) []string {
	logMu.Lock()
	defer logMu.Unlock()
	var out []string
	start := max(0, recentNext-recentLogSize)
	for i := recentNext - 1; i >= start && len(out) < n; i-- {
		if line := recentLines[i%recentLogSize]; filter == "" || strings.Contains(line, filter) {
			out = append(out, line)
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func emit(file *FileLogger, fallback io.Writer, format string, args []any) {
	line := time.Now().UTC().Format("2006-01-02T15:04:05.000Z") + " " + fmt.Sprintf(format, args...) + "\n"
	recentLines[recentNext%recentLogSize] = strings.TrimSuffix(line, "\n")
	recentNext++
	if file != nil {
		if err := file.WriteLine(line); err == nil {
			return
		} else {
			fmt.Fprintf(os.Stderr, "log: cannot write %s: %v\n", file.path, err)
		}
	}
	io.WriteString(fallback, line)
}

// logf writes one timestamped line of normal activity.
func logf(format string, args ...any) {
	logMu.Lock()
	defer logMu.Unlock()
	emit(sinkOut, logOut, format, args)
}

// errorf writes one timestamped line about a problem.
func errorf(format string, args ...any) {
	logMu.Lock()
	defer logMu.Unlock()
	emit(sinkErr, logErr, format, args)
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
