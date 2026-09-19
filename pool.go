package main

import (
	"sync"
	"sync/atomic"
	"time"
)

// BufferPool hands out fixed-size byte slices through a buffered channel.
//
// Borrow and return never block: borrowing from an empty pool allocates a new
// buffer, and returning to a full pool drops the buffer for the GC. In steady
// state every buffer is reused, so relaying data allocates nothing. Buffers
// are not cleared on reuse: callers only look at the bytes they just read.
type BufferPool struct {
	size      int
	free      chan []byte
	fullSince atomic.Int64
	done      chan struct{}
	stopOnce  sync.Once
}

func NewBufferPool(size, maxIdle int) *BufferPool {
	p := &BufferPool{size: size, free: make(chan []byte, maxIdle), done: make(chan struct{})}
	go p.trimIdle()
	return p
}

func (p *BufferPool) Get() []byte {
	select {
	case b := <-p.free:
		// A borrower broke a full idle period. A later return that refills the
		// queue starts a fresh trimming interval.
		if len(p.free) < cap(p.free) {
			p.fullSince.Store(0)
		}
		return b
	default:
		return make([]byte, p.size)
	}
}

func (p *BufferPool) Put(b []byte) {
	if cap(b) != p.size {
		return // not ours (e.g. a grown ClientHello buffer)
	}
	select {
	case p.free <- b[:p.size]:
		if cap(p.free) > 0 && len(p.free) == cap(p.free) {
			p.fullSince.CompareAndSwap(0, time.Now().UnixNano())
		}
	default: // pool is full: let the GC have it
	}
}

// trimIdle sheds half the parked buffers after a pool has stayed at its peak
// for a minute.  It leaves a useful warm working set but lets a burst release
// memory without waiting for a configuration reload or a future connection.
func (p *BufferPool) trimIdle() {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-p.done:
			return
		case now := <-tick.C:
			since := p.fullSince.Load()
			if since == 0 || now.Sub(time.Unix(0, since)) < time.Minute || len(p.free) <= cap(p.free)/2 {
				continue
			}
		trim:
			for len(p.free) > cap(p.free)/2 {
				// Get may race us after the len check.  Trimming is best-effort:
				// never let its maintenance goroutine wait for a returned buffer.
				select {
				case <-p.done:
					return
				case <-p.free:
				default:
					break trim
				}
			}
			p.fullSince.Store(0)
		}
	}
}

// Stop stops only the janitor. Buffers already borrowed by old runtimes can
// still be returned safely while those connections finish.
func (p *BufferPool) Stop() { p.stopOnce.Do(func() { close(p.done) }) }

// Idle is the number of buffers parked in the pool.
func (p *BufferPool) Idle() int { return len(p.free) }
