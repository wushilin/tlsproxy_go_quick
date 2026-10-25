package main

import "time"

// Lingering: batching a busy stream that arrives a little at a time.
//
// Every chunk the relay moves costs a wake-up and a read and a write (or two
// splices), however small it is. So when a read comes back short in the middle
// of a stream, the direction sleeps lingerTime, tops the chunk up with what
// arrived meanwhile (without waiting for more), and moves it all at once. Each
// direction decides alone, from its own reads.
//
// lingering is the mode. Linger in: a read that is not full sleeps and tops up.
// Linger out: every read moves at once. A top-up that gets nothing flips it
// out: nothing kept arriving, as with a request waiting for its reply or a
// stream too slow to batch. Every hintRecheck it flips back in, and the next
// linger tells again. Reads further apart than lingerGap are not a stream and
// never linger.
//
// full is the size hint: a read this big moves at once. It starts at the chunk
// and drops when a linger shows that reads can't get that big:
//   - The top-up took less than the socket held (the mover could tell, with
//     one ioctl, on the first linger after each recheck): the kernel pipe
//     filled. From a network card each packet takes one of the pipe's slots,
//     so a 16-slot pipe holds 16 packets (23168 bytes at MSS 1448), while
//     local traffic fills it to the byte.
//   - The top-up filled the chunk: the stream outruns a linger, so a read this
//     big moves at once from now on. This is what keeps a bulk download
//     through terminated TLS at full speed: a TLS read returns one record (16
//     KiB at most), short of the chunk even when much more is waiting.
//
// Any read bigger than full raises it.
//
// A speed limit does not change this. Below the limit a stream reads short like
// any other; at the limit, bytes queue while the limiter waits and the reads
// come back full. The limiter charges the bytes actually moved, so a linger
// does not change the enforced speed.
const (
	// lingerTime is how long a short read waits for more, once.
	lingerTime = 5 * time.Millisecond
	// lingerGap: reads further apart than this are not one stream.
	lingerGap = 5 * time.Millisecond
	// hintRecheck is how often lingering is tried again and full measured.
	hintRecheck = 100 * time.Millisecond
	// topUpWait bounds a top-up that cannot be made non-blocking (a buffered
	// read): long enough that the read is attempted at all, short enough to
	// count as not waiting.
	topUpWait = 200 * time.Microsecond
)

// batcher is one direction's lingering state. The zero value is ready; off
// (low_latency) never lingers.
type batcher struct {
	off                bool
	lingering, measure bool
	full               int
	lastRead, checked  time.Time
}

// batch is called after each read of n bytes (n > 0, no error) and returns how
// many bytes the mover holds now, and any error a top-up ran into: the bytes
// held are moved first, then the error ends the direction like a read's would.
func (b *batcher) batch(m mover, n int) (int, error) {
	if b.off {
		return n, nil
	}
	now := time.Now()
	if now.Sub(b.checked) >= hintRecheck {
		b.checked, b.lingering, b.full, b.measure = now, true, m.chunk(), true
	}
	if !b.lingering || n >= b.full || now.Sub(b.lastRead) >= lingerGap {
		b.full = max(b.full, n)
		b.lastRead = now
		return n, nil
	}
	time.Sleep(lingerTime)
	waiting := -1
	if b.measure {
		waiting, b.measure = m.waiting(), false
	}
	room := m.chunk() - n
	more, err := m.topUp(n)
	switch {
	case more == room:
		b.full = n // the stream outruns a linger
	case more < min(waiting, room):
		b.full = n + more // the pipe filled: it holds no more than this
	default:
		if more == 0 && err == nil {
			b.lingering = false // nothing arrived: linger out
		}
		b.full = max(b.full, n+more)
	}
	b.lastRead = time.Now()
	return n + more, err
}
