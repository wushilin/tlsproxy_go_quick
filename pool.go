package main

// BufferPool hands out fixed-size byte slices through a buffered channel.
//
// Borrow and return never block: borrowing from an empty pool allocates a new
// buffer, and returning to a full pool drops the buffer for the GC. In steady
// state every buffer is reused, so relaying data allocates nothing. Buffers
// are not cleared on reuse: callers only look at the bytes they just read.
type BufferPool struct {
	size int
	free chan []byte
}

func NewBufferPool(size, maxIdle int) *BufferPool {
	return &BufferPool{size: size, free: make(chan []byte, maxIdle)}
}

func (p *BufferPool) Get() []byte {
	select {
	case b := <-p.free:
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
	default: // pool is full: let the GC have it
	}
}

// Idle is the number of buffers parked in the pool.
func (p *BufferPool) Idle() int { return len(p.free) }
