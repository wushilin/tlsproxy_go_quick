//go:build linux

package main

// Zero-copy relaying for passed-through connections: splice(2) moves the bytes
// socket -> kernel pipe -> socket, so they are never copied into this process.
// Only plain TCP on both ends qualifies; a terminated side has to be decrypted
// here, so it keeps the buffered copy.

import (
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"unsafe"
)

const (
	spliceMove     = 0x1 // SPLICE_F_MOVE
	spliceNonblock = 0x2 // SPLICE_F_NONBLOCK
	fSetPipeSize   = 1031
	fGetPipeSize   = 1032
)

// spliceMover is one direction's kernel pipe. The pipe is empty whenever read
// is called: write drains it completely or the direction ends.
//
// Go's TCPConn.ReadFrom splices too, but it returns only at EOF, so the relay
// could not count bytes, note activity for the idle timer or apply its write
// deadline per chunk. This does one splice step per read and write instead.
//
// Both sockets stay non-blocking: on EAGAIN the RawConn callback returns
// false and the goroutine parks in the netpoller, so deadlines and a Close
// from the other direction interrupt a splice exactly like a Read or Write.
type spliceMover struct {
	from, to     *net.TCPConn
	src, dst     syscall.RawConn
	pipe         [2]int // read end, write end
	size, queued int
	spliced      bool // something went through, so falling back is no longer possible
}

// newSpliceMover returns nil when the direction cannot be spliced: a side is
// not plain TCP, the ClientHello replay is not finished, or no pipe is
// available (EMFILE, say). The caller then copies through a buffer.
func newSpliceMover(from, to duplex, size int) mover {
	src, dst := plainTCP(from), plainTCP(to)
	if src == nil || dst == nil {
		return nil
	}
	m := &spliceMover{from: src, to: dst}
	var err error
	if m.src, err = src.SyscallConn(); err != nil {
		return nil
	}
	if m.dst, err = dst.SyscallConn(); err != nil {
		return nil
	}
	if err := syscall.Pipe2(m.pipe[:], syscall.O_CLOEXEC|syscall.O_NONBLOCK); err != nil {
		return nil
	}
	// Best effort: past the per-user pipe allowance (fs.pipe-user-pages-soft)
	// the kernel refuses to grow pipes and may even hand out smaller ones.
	// Splicing still works, in smaller steps.
	syscall.Syscall(syscall.SYS_FCNTL, uintptr(m.pipe[1]), fSetPipeSize, uintptr(size))
	m.size = size
	if got, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(m.pipe[1]), fGetPipeSize, 0); errno == 0 && int(got) < size {
		m.size = int(got)
	}
	return m
}

// plainTCP is the TCP socket under c, if c adds nothing on top of it.
func plainTCP(c duplex) *net.TCPConn {
	switch c := c.(type) {
	case *net.TCPConn:
		return c
	case *proxyConn:
		if len(c.prefix) == 0 {
			tc, _ := c.Conn.(*net.TCPConn)
			return tc
		}
	}
	return nil
}

func (m *spliceMover) chunk() int { return m.size }

func (m *spliceMover) read() (int, error) {
	var n int64
	var serr error
	err := m.src.Read(func(fd uintptr) bool {
		n, serr = spliceRetry(int(fd), m.pipe[1], m.size)
		return serr != syscall.EAGAIN
	})
	if err == nil {
		err = serr
	}
	switch {
	case err == nil && n == 0:
		return 0, io.EOF
	case err == nil:
		m.spliced = true
		m.queued = int(n)
		return int(n), nil
	case !m.spliced && errors.Is(err, syscall.EINVAL):
		// The kernel will not splice this socket; nothing was consumed.
		return 0, errNoSplice
	}
	return 0, m.opError("read", m.from, err)
}

// topUp splices what the socket holds into the room left in the pipe. The
// callback never asks to wait: EAGAIN just means nothing more came.
func (m *spliceMover) topUp(int) (int, error) {
	room := m.size - m.queued
	if room <= 0 {
		return 0, nil
	}
	var n int64
	var serr error
	err := m.src.Read(func(fd uintptr) bool {
		n, serr = spliceRetry(int(fd), m.pipe[1], room)
		return true
	})
	if err == nil {
		err = serr
	}
	switch {
	case err == nil && n == 0:
		return 0, io.EOF
	case err == nil:
		m.queued += int(n)
		return int(n), nil
	case err == syscall.EAGAIN:
		return 0, nil
	}
	return 0, m.opError("read", m.from, err)
}

// waiting is the socket's receive queue, from one ioctl.
func (m *spliceMover) waiting() int {
	n := int32(-1)
	m.src.Control(func(fd uintptr) {
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCINQ, uintptr(unsafe.Pointer(&n))); e != 0 {
			n = -1
		}
	})
	return int(n)
}

func (m *spliceMover) write(int) (int, error) {
	written := 0
	for m.queued > 0 {
		var n int64
		var serr error
		err := m.dst.Write(func(fd uintptr) bool {
			n, serr = spliceRetry(m.pipe[0], int(fd), m.queued)
			return serr != syscall.EAGAIN
		})
		if err == nil {
			err = serr
		}
		if err == nil && n == 0 {
			err = io.ErrShortWrite // no progress; don't spin
		}
		if err != nil {
			return written, m.opError("write", m.to, err)
		}
		m.queued -= int(n)
		written += int(n)
	}
	return written, nil
}

func (m *spliceMover) close() {
	syscall.Close(m.pipe[0])
	syscall.Close(m.pipe[1])
}

// opError dresses a raw errno like the error a Read or Write would have
// returned ("write tcp a->b: broken pipe"). Errors from RawConn (a deadline,
// a closed connection) already are.
func (m *spliceMover) opError(op string, c *net.TCPConn, err error) error {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return err
	}
	return &net.OpError{Op: op, Net: "tcp", Source: c.LocalAddr(), Addr: c.RemoteAddr(), Err: os.NewSyscallError("splice", errno)}
}

func spliceRetry(from, to, n int) (int64, error) {
	for {
		moved, err := syscall.Splice(from, nil, to, nil, n, spliceMove|spliceNonblock)
		if err != syscall.EINTR {
			return moved, err
		}
	}
}
