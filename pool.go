package main

import (
	"sync"
	"sync/atomic"
	"time"
)

// BufferPool hands out fixed-size byte slices from a lock-free ring.
//
// Borrow and return never block and take no lock: borrowing from an empty
// pool allocates a new buffer, and returning to a full pool drops the buffer
// for the GC. In steady state every buffer is reused, so relaying data
// allocates nothing. Buffers are not cleared on reuse: callers only look at
// the bytes they just read.
type BufferPool struct {
	size      int
	maxIdle   int
	free      *ring[[]byte]
	fullSince atomic.Int64
	done      chan struct{}
	stopOnce  sync.Once
}

func NewBufferPool(size, maxIdle int) *BufferPool {
	p := &BufferPool{size: size, maxIdle: maxIdle, free: newRing[[]byte](max(maxIdle, 1)), done: make(chan struct{})}
	go p.trimIdle()
	return p
}

func (p *BufferPool) Get() []byte {
	if b, ok := p.free.TryPop(); ok {
		// A borrower broke a full idle period. A later return that refills the
		// pool starts a fresh trimming interval.
		if p.free.Len() < p.maxIdle {
			p.fullSince.Store(0)
		}
		return b
	}
	return make([]byte, p.size)
}

func (p *BufferPool) Put(b []byte) {
	if cap(b) != p.size || p.maxIdle <= 0 {
		return // not ours (e.g. a grown ClientHello buffer), or pooling is off
	}
	// The ring may round its size up: keep at most maxIdle all the same.
	if p.free.Len() >= p.maxIdle || !p.free.TryPush(b[:p.size]) {
		return // pool is full: let the GC have it
	}
	if p.free.Len() >= p.maxIdle {
		p.fullSince.CompareAndSwap(0, time.Now().UnixNano())
	}
}

// trimIdle sheds half the parked buffers after a pool has stayed at its peak
// for a minute. It leaves a useful warm working set but lets a burst release
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
			if since == 0 || now.Sub(time.Unix(0, since)) < time.Minute || p.free.Len() <= p.maxIdle/2 {
				continue
			}
			for p.free.Len() > p.maxIdle/2 {
				if _, ok := p.free.TryPop(); !ok {
					break // borrowers got there first
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
func (p *BufferPool) Idle() int { return p.free.Len() }
