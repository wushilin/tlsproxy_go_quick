package main

// Lock-free building blocks for the serving path: whatever a connection does
// between accept and close never waits for another connection's lock.
//
// ring is a bounded multi-producer multi-consumer queue (Dmitry Vyukov's
// design): each cell carries a sequence number saying whose turn it is, and
// producers and consumers claim positions with one compare-and-swap. TryPush
// and TryPop never block; a full or empty ring just says so.

import (
	"hash/maphash"
	"net/netip"
	"sync"
	"sync/atomic"
)

type ringCell[T any] struct {
	seq atomic.Uint64
	val T
}

type ring[T any] struct {
	mask uint64
	_    [56]byte // keep the two counters on separate cache lines
	head atomic.Uint64
	_    [56]byte
	tail atomic.Uint64
	_    [56]byte
	cell []ringCell[T]
}

// newRing makes a ring for at least capacity items (rounded up to a power of
// two, at least 2).
func newRing[T any](capacity int) *ring[T] {
	n := uint64(2)
	for n < uint64(capacity) {
		n <<= 1
	}
	r := &ring[T]{mask: n - 1, cell: make([]ringCell[T], n)}
	for i := range r.cell {
		r.cell[i].seq.Store(uint64(i))
	}
	return r
}

// TryPush adds v, or reports false when the ring is full.
func (r *ring[T]) TryPush(v T) bool {
	for {
		pos := r.tail.Load()
		c := &r.cell[pos&r.mask]
		switch seq := c.seq.Load(); {
		case seq == pos: // free: claim it
			if r.tail.CompareAndSwap(pos, pos+1) {
				c.val = v
				c.seq.Store(pos + 1) // now a consumer may take it
				return true
			}
		case seq < pos: // still holds an item from one lap ago: full
			return false
		}
		// Another producer got there first: try the next position.
	}
}

// TryPop takes the oldest item, or reports false when the ring is empty.
func (r *ring[T]) TryPop() (T, bool) {
	for {
		pos := r.head.Load()
		c := &r.cell[pos&r.mask]
		switch seq := c.seq.Load(); {
		case seq == pos+1: // filled: claim it
			if r.head.CompareAndSwap(pos, pos+1) {
				v := c.val
				var zero T
				c.val = zero                  // let the GC have it
				c.seq.Store(pos + r.mask + 1) // free for the producer one lap ahead
				return v, true
			}
		case seq < pos+1: // not filled yet: empty
			var zero T
			return zero, false
		}
	}
}

// Len is about how many items are queued (exact when nothing is in flight).
func (r *ring[T]) Len() int {
	head, tail := r.head.Load(), r.tail.Load()
	if tail < head {
		return 0
	}
	return int(tail - head)
}

// Cap is how many items the ring holds.
func (r *ring[T]) Cap() int { return len(r.cell) }

// syncMap is a typed sync.Map that also keeps its length. Since Go 1.24
// sync.Map is a concurrent hash-trie: Load never locks, and Store/Delete lock
// only the one small node they change, so connections that touch different
// keys don't wait for each other.
type syncMap[K comparable, V any] struct {
	m sync.Map
	n atomic.Int64
}

// init makes the map ready now: an untouched sync.Map sets itself up under a
// lock on first use, which the first burst of connections would wait for.
func (m *syncMap[K, V]) init() {
	var zero K
	m.m.Load(zero)
}

func (m *syncMap[K, V]) Load(k K) (V, bool) {
	v, ok := m.m.Load(k)
	if !ok {
		var zero V
		return zero, false
	}
	return v.(V), true
}

// LoadOrMake returns the value for k, making it with mk if there is none.
// When two callers race, both get the one that was stored first.
func (m *syncMap[K, V]) LoadOrMake(k K, mk func() V) V {
	if v, ok := m.m.Load(k); ok {
		return v.(V)
	}
	v, loaded := m.m.LoadOrStore(k, mk())
	if !loaded {
		m.n.Add(1)
	}
	return v.(V)
}

func (m *syncMap[K, V]) Store(k K, v V) {
	if _, loaded := m.m.Swap(k, v); !loaded {
		m.n.Add(1)
	}
}

func (m *syncMap[K, V]) Delete(k K) {
	if _, loaded := m.m.LoadAndDelete(k); loaded {
		m.n.Add(-1)
	}
}

// Range calls f for each entry until it returns false. Entries added or
// removed meanwhile may or may not be seen.
func (m *syncMap[K, V]) Range(f func(K, V) bool) {
	m.m.Range(func(k, v any) bool { return f(k.(K), v.(V)) })
}

// Len is the number of entries (exact when nothing is changing).
func (m *syncMap[K, V]) Len() int { return int(m.n.Load()) }

// connTable is the registry of open connections, lock-free on both sides:
// a connection claims a free slot with one compare-and-swap and clears it
// when it closes. Slots live in fixed segments that never move; when the
// table is half full a new segment is appended to the directory, which is
// replaced whole (an ArcSwap). Readers (the console, stats) scan the slots.
type connTable struct {
	dir   atomic.Pointer[[]*connSegment]
	count atomic.Int64
}

const connSegmentSize = 1024

type connSegment [connSegmentSize]atomic.Pointer[ConnState]

func (t *connTable) segments() []*connSegment {
	if d := t.dir.Load(); d != nil {
		return *d
	}
	return nil
}

// grow appends a segment unless another caller already did (have is the
// directory length the caller saw).
func (t *connTable) grow(have int) {
	for {
		old := t.dir.Load()
		var segs []*connSegment
		if old != nil {
			segs = *old
		}
		if len(segs) > have {
			return
		}
		next := append(append([]*connSegment(nil), segs...), new(connSegment))
		if t.dir.CompareAndSwap(old, &next) {
			return
		}
	}
}

// add claims a slot for c and returns it, for remove.
func (t *connTable) add(c *ConnState) *atomic.Pointer[ConnState] {
	for {
		segs := t.segments()
		if n := len(segs) * connSegmentSize; n == 0 || t.count.Load()+1 > int64(n)/2 {
			t.grow(len(segs)) // keep it at most half full, so a free slot is near
			continue
		}
		n := len(segs) * connSegmentSize
		start := int(c.ID % uint64(n)) // spread connections over the table
		for i := range n {
			j := (start + i) % n
			slot := &segs[j/connSegmentSize][j%connSegmentSize]
			if slot.Load() == nil && slot.CompareAndSwap(nil, c) {
				t.count.Add(1)
				return slot
			}
		}
		t.grow(len(segs)) // every slot taken meanwhile: make room
	}
}

func (t *connTable) remove(slot *atomic.Pointer[ConnState]) {
	slot.Store(nil)
	t.count.Add(-1)
}

// Range calls f for each open connection until it returns false.
func (t *connTable) Range(f func(*ConnState) bool) {
	for _, seg := range t.segments() {
		for i := range seg {
			if c := seg[i].Load(); c != nil && !f(c) {
				return
			}
		}
	}
}

// Load finds an open connection by ID (a scan: for the console, not the
// serving path).
func (t *connTable) Load(id uint64) (*ConnState, bool) {
	var found *ConnState
	t.Range(func(c *ConnState) bool {
		if c.ID == id {
			found = c
			return false
		}
		return true
	})
	return found, found != nil
}

func (t *connTable) Len() int { return int(t.count.Load()) }

// sourceCounts counts handshakes in progress per source without a map: a
// fixed array of atomic counters, indexed by a keyed hash of the address.
// Two sources that hash alike share one counter (and so one limit); the key
// is random per process, so nobody can aim for that.
type sourceCounts struct {
	seed maphash.Seed
	n    [1 << 16]atomic.Int32
}

func newSourceCounts() *sourceCounts { return &sourceCounts{seed: maphash.MakeSeed()} }

func (s *sourceCounts) counter(a netip.Addr) *atomic.Int32 {
	b := a.As16()
	return &s.n[maphash.Bytes(s.seed, b[:])&(1<<16-1)]
}

// hostTable holds the per-name counters: names come from clients, so a new
// one can arrive on any connection. It is a fixed open-addressing table that
// never deletes: a new name claims an empty slot with compare-and-swap, a
// known one is found by reading. Beyond maxHostStats names, the rest share
// "(other)" (the table has room for that and for racing inserts).
type hostTable struct {
	seed  maphash.Seed
	slots [hostTableSize]atomic.Pointer[hostEntry]
	n     atomic.Int64
}

const hostTableSize = 4096 // a power of two, comfortably over maxHostStats

type hostEntry struct {
	name  string
	stats HostStats
}

func newHostTable() *hostTable { return &hostTable{seed: maphash.MakeSeed()} }

func (t *hostTable) get(name string) *HostStats {
	if name != "(other)" && t.n.Load() >= maxHostStats {
		if h := t.find(name, false); h != nil {
			return h
		}
		name = "(other)"
	}
	if h := t.find(name, true); h != nil {
		return h
	}
	return t.find("(other)", true) // only if every slot is taken, which the cap prevents
}

// find looks name up, adding it when add is set and it is not there.
func (t *hostTable) find(name string, add bool) *HostStats {
	h := maphash.String(t.seed, name)
	for i := range uint64(hostTableSize) {
		slot := &t.slots[(h+i)&(hostTableSize-1)]
		e := slot.Load()
		if e == nil {
			if !add {
				return nil
			}
			fresh := &hostEntry{name: name}
			if slot.CompareAndSwap(nil, fresh) {
				t.n.Add(1)
				return &fresh.stats
			}
			e = slot.Load() // another connection took this slot first
		}
		if e.name == name {
			return &e.stats
		}
	}
	return nil
}

// Range calls f for each name until it returns false.
func (t *hostTable) Range(f func(string, *HostStats) bool) {
	for i := range t.slots {
		if e := t.slots[i].Load(); e != nil && !f(e.name, &e.stats) {
			return
		}
	}
}

func (t *hostTable) Len() int { return int(t.n.Load()) }
