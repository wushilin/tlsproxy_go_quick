package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"sync/atomic"
)

// LogConfig is the [logging] section of the config.
type LogConfig struct {
	Stdout        string // file for normal activity; "" = the process's stdout
	Stderr        string // file for problems; "" = the process's stderr
	MaxSize       int64  // rotate once the file has reached this many bytes
	MaxKeep       int    // rotated generations kept: file.1 .. file.<MaxKeep>
	CompressAfter int    // generations above this number are gzip-compressed
}

func defaultLogConfig() LogConfig {
	return LogConfig{MaxSize: 15 << 20, MaxKeep: 10, CompressAfter: 3}
}

// FileLogger is a size-rotated log file with numbered generations (file.1 is
// the newest).
//
// Rotation itself is a handful of renames done inline. Compressing the
// generation that just crossed CompressAfter is slow, so it runs in a
// goroutine under the compress guard: while the guard is held no further
// rotation happens, so the numbering can't shift under the compressor. The
// live file simply outgrows MaxSize until the guard is released.
//
// Callers serialise WriteLine (logf/errorf hold logMu).
type FileLogger struct {
	cfg            LogConfig
	path           string
	file           *os.File
	size           int64
	compressing    atomic.Bool
	rotationFailed atomic.Bool   // do not repeat a partly completed generation shift
	idle           chan struct{} // closed when the current compression is done
}

func generationName(path string, n int, gz bool) string {
	if gz {
		return fmt.Sprintf("%s.%d.gz", path, n)
	}
	return fmt.Sprintf("%s.%d", path, n)
}

func openAppend(path string) (*os.File, int64, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, st.Size(), nil
}

func OpenFileLogger(path string, cfg LogConfig) (*FileLogger, error) {
	f, size, err := openAppend(path)
	if err != nil {
		return nil, err
	}
	return &FileLogger{cfg: cfg, path: path, file: f, size: size}, nil
}

func (l *FileLogger) WriteLine(line string) error {
	// Compress guard: never rotate while a compression is still running.
	if l.size >= l.cfg.MaxSize && !l.compressing.Load() && !l.rotationFailed.Load() {
		if err := l.rotate(); err != nil {
			l.rotationFailed.Store(true)
			return err
		}
	}
	n, err := io.WriteString(l.file, line)
	l.size += int64(n)
	return err
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (l *FileLogger) rotate() error {
	keep := l.cfg.MaxKeep
	// Shift generations up, oldest first; whatever falls off the end goes.
	for n := max(keep, 1); n >= 1; n-- {
		for _, gz := range []bool{false, true} {
			from := generationName(l.path, n, gz)
			if !exists(from) {
				continue
			}
			var err error
			if n >= keep {
				err = os.Remove(from)
			} else {
				err = os.Rename(from, generationName(l.path, n+1, gz))
			}
			if err != nil {
				return err
			}
		}
	}
	l.file.Close()
	var err error
	if keep == 0 {
		err = os.Remove(l.path)
	} else {
		err = os.Rename(l.path, generationName(l.path, 1, false))
	}
	if err != nil {
		// The old descriptor is closed before a rename (required on some
		// platforms). Recover a usable live writer so a failed rotation does
		// not turn every subsequent log line into a stderr fallback.
		if file, size, reopenErr := openAppend(l.path); reopenErr == nil {
			l.file, l.size = file, size
		}
		return err
	}
	if l.file, l.size, err = openAppend(l.path); err != nil {
		return err
	}

	// Take the guard, then compress every generation past CompressAfter that
	// is still plain (normally just the one that crossed the line).
	l.compressing.Store(true)
	idle := make(chan struct{})
	l.idle = idle
	go func() {
		defer close(idle)
		defer l.compressing.Store(false)
		for n := l.cfg.CompressAfter + 1; n <= keep; n++ {
			plain := generationName(l.path, n, false)
			if !exists(plain) {
				continue
			}
			if err := gzipFile(plain, generationName(l.path, n, true)); err != nil {
				// Keep the plain file; it is retried at the next rotation.
				fmt.Fprintf(os.Stderr, "log: cannot compress %s: %v\n", plain, err)
				continue
			}
			os.Remove(plain)
		}
	}()
	return nil
}

// waitIdle waits for the background compression to finish (tests).
func (l *FileLogger) waitIdle() {
	if l.idle != nil {
		<-l.idle
	}
}

// Close waits until the logger no longer has a compressor manipulating its
// generation files. This matters when a config reload opens a replacement for
// the same path: the replacement must not rotate those files concurrently.
func (l *FileLogger) Close() error {
	l.waitIdle()
	return l.file.Close()
}

// gzipFile compresses src into dst (written via a temporary file, so dst
// only ever appears complete).
func gzipFile(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(tmp)
		}
	}()
	zw := gzip.NewWriter(out)
	if _, err = io.Copy(zw, in); err == nil {
		err = zw.Close()
	}
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// generations lists the existing generations of path, newest (.1) first.
func generations(path string, maxN int) []string {
	var out []string
	for n := 1; n <= maxN; n++ {
		for _, gz := range []bool{false, true} {
			if p := generationName(path, n, gz); exists(p) {
				out = append(out, p)
			}
		}
	}
	return out
}
