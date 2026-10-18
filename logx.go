package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Two streams, like a daemon's stdout and stderr: normal activity (logf) and
// problems (errorf). Each goes to the process's own stdout/stderr or, when
// [logging] names a file for it, to a rotating file (see rotate.go).
//
// In the running proxy (StartAsyncLogging) a log call only puts the line in
// a lock-free ring; a background goroutine writes the queued lines out ten
// times a second, and at once after a problem line. Connection handlers and
// the accept loop therefore never wait for a disk, a stalled pipe or each
// other. If the destination cannot keep up, lines beyond maxPendingLog bytes
// (or maxPendingLines) are dropped and counted rather than held. Without
// StartAsyncLogging (tests, --test) lines are written synchronously.
var (
	flushMu sync.Mutex             // serialises flushes, keeps lines in order; taken before logMu
	logMu   sync.Mutex             // the destinations below, and synchronous writes
	logOut  io.Writer  = os.Stdout // where logf goes without a file (tests swap it)
	logErr  io.Writer  = os.Stderr
	sinkCfg *LogConfig
	sinkOut *FileLogger
	sinkErr *FileLogger

	logAsync      atomic.Bool
	logQueue      = newRing[queuedLine](maxPendingLines) // both streams, in the order logged
	pendingBytes  atomic.Int64
	droppedLog    atomic.Int64
	problemQueued atomic.Bool // a problem line is waiting: flushNow was sent
	flushNow      = make(chan struct{}, 1)
)

const (
	maxPendingLog    = 4 << 20
	maxPendingLines  = 1 << 15
	logFlushInterval = 100 * time.Millisecond
)

type queuedLine struct {
	text    string
	problem bool
}

// StartAsyncLogging moves writing out of the callers' way (see above). Call
// FlushLogs before the process exits.
func StartAsyncLogging() {
	if logAsync.Swap(true) {
		return
	}
	go func() {
		tick := time.NewTicker(logFlushInterval)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
			case <-flushNow:
			}
			FlushLogs()
		}
	}()
}

// FlushLogs writes out everything logged so far.
func FlushLogs() {
	flushMu.Lock()
	defer flushMu.Unlock()
	flushLocked()
}

func flushLocked() {
	problemQueued.Store(false)
	logMu.Lock()
	outFile, errFile, outW, errW := sinkOut, sinkErr, logOut, logErr
	logMu.Unlock()
	// Consecutive lines of a stream are written together, so a flush is a few
	// large writes, and the two streams come out in the order they were
	// logged when they share a destination.
	var buf strings.Builder
	problem := false
	write := func() {
		if buf.Len() == 0 {
			return
		}
		if problem {
			writeLog(errFile, errW, buf.String())
		} else {
			writeLog(outFile, outW, buf.String())
		}
		buf.Reset()
	}
	for {
		l, ok := logQueue.TryPop()
		if !ok {
			break
		}
		pendingBytes.Add(-int64(len(l.text)))
		if l.problem != problem || buf.Len() > 1<<20 {
			write()
			problem = l.problem
		}
		buf.WriteString(l.text)
	}
	write()
	if dropped := droppedLog.Swap(0); dropped > 0 {
		writeLog(errFile, errW, time.Now().UTC().Format("2006-01-02T15:04:05.000Z")+
			fmt.Sprintf(" log: %d lines were dropped: the log destination could not keep up\n", dropped))
	}
}

// writeLog writes whole lines to a stream's destination.
func writeLog(file *FileLogger, fallback io.Writer, text string) {
	if file != nil {
		if err := file.WriteLines(text); err == nil {
			return
		} else {
			fmt.Fprintf(os.Stderr, "log: cannot write %s: %v\n", file.path, err)
		}
	}
	io.WriteString(fallback, text)
}

// ConfigureLogging applies the [logging] settings (at startup and on every
// config reload). On error the previous destinations stay in use.
func ConfigureLogging(cfg LogConfig) error {
	flushMu.Lock() // nothing is being written while destinations change
	defer flushMu.Unlock()
	flushLocked() // what was logged so far belongs to the old destinations
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
	recentLines [recentLogSize]atomic.Pointer[recentLine]
	recentNext  atomic.Uint64 // lines ever stored; line n is in slot n % size
)

type recentLine struct {
	n    uint64
	text string
}

// RecentLog returns up to n of the newest lines (oldest first) that contain
// filter ("" = all).
func RecentLog(n int, filter string) []string {
	out := []string{} // never nil: the console's JSON says [] rather than null
	next := recentNext.Load()
	start := uint64(0)
	if next > recentLogSize {
		start = next - recentLogSize
	}
	for i := next; i > start && len(out) < n; i-- {
		l := recentLines[(i-1)%recentLogSize].Load()
		if l == nil || l.n != i-1 { // not written yet, or already overwritten by a newer line
			continue
		}
		if filter == "" || strings.Contains(l.text, filter) {
			out = append(out, l.text)
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// emit records one line. In the running proxy it takes no lock.
func emit(problem bool, format string, args []any) {
	line := time.Now().UTC().Format("2006-01-02T15:04:05.000Z") + " " + fmt.Sprintf(format, args...) + "\n"
	n := recentNext.Add(1) - 1
	recentLines[n%recentLogSize].Store(&recentLine{n: n, text: strings.TrimSuffix(line, "\n")})
	if !logAsync.Load() {
		logMu.Lock()
		defer logMu.Unlock()
		if problem {
			writeLog(sinkErr, logErr, line)
		} else {
			writeLog(sinkOut, logOut, line)
		}
		return
	}
	if pendingBytes.Add(int64(len(line))) > maxPendingLog {
		pendingBytes.Add(-int64(len(line)))
		droppedLog.Add(1)
		return
	}
	if !logQueue.TryPush(queuedLine{line, problem}) {
		pendingBytes.Add(-int64(len(line)))
		droppedLog.Add(1)
		return
	}
	// Problems are worth seeing at once: wake the writer, once per flush.
	if problem && problemQueued.CompareAndSwap(false, true) {
		select {
		case flushNow <- struct{}{}:
		default:
		}
	}
}

// logf writes one timestamped line of normal activity.
func logf(format string, args ...any) { emit(false, format, args) }

// errorf writes one timestamped line about a problem.
func errorf(format string, args ...any) { emit(true, format, args) }

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
