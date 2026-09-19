package main

import "sync"

// lru is a capped, thread-safe LRU map from string to V: a map from key to
// slot index plus a recency list threaded through a slice of slots. When
// full, the least recently used slot is reused in place.
type lru[V any] struct {
	mu         sync.Mutex
	cap        int
	index      map[string]int
	slots      []lruSlot[V]
	head, tail int // most / least recently used; -1 when empty
}

type lruSlot[V any] struct {
	key        string
	val        V
	prev, next int
}

func newLRU[V any](capacity int) *lru[V] {
	return &lru[V]{cap: capacity, index: make(map[string]int), head: -1, tail: -1}
}

func (l *lru[V]) Get(key string) (V, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	i, ok := l.index[key]
	if !ok {
		var zero V
		return zero, false
	}
	l.unlink(i)
	l.pushFront(i)
	return l.slots[i].val, true
}

func (l *lru[V]) Put(key string, val V) {
	if l.cap == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if i, ok := l.index[key]; ok {
		l.slots[i].val = val
		l.unlink(i)
		l.pushFront(i)
		return
	}
	var i int
	if len(l.slots) < l.cap {
		l.slots = append(l.slots, lruSlot[V]{})
		i = len(l.slots) - 1
	} else {
		i = l.tail // evict the least recently used, reuse its slot
		l.unlink(i)
		delete(l.index, l.slots[i].key)
	}
	l.slots[i].key, l.slots[i].val = key, val
	l.index[key] = i
	l.pushFront(i)
}

func (l *lru[V]) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.index)
}

func (l *lru[V]) Contains(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.index[key]
	return ok
}

func (l *lru[V]) unlink(i int) {
	s := l.slots[i]
	if s.prev == -1 {
		l.head = s.next
	} else {
		l.slots[s.prev].next = s.next
	}
	if s.next == -1 {
		l.tail = s.prev
	} else {
		l.slots[s.next].prev = s.prev
	}
}

func (l *lru[V]) pushFront(i int) {
	l.slots[i].prev, l.slots[i].next = -1, l.head
	if l.head == -1 {
		l.tail = i
	} else {
		l.slots[l.head].prev = i
	}
	l.head = i
}

// RouteCache caches routing decisions by lowercased SNI. Allowed and denied
// names live in separate LRUs with separate caps: allowed names are few and
// concentrated, denied names can be many and random, so a flood of junk names
// can only evict other junk. Routing errors count as denials.
type RouteCache struct {
	allow, deny *lru[Decision]
}

func NewRouteCache(allowCap, denyCap int) *RouteCache {
	return &RouteCache{allow: newLRU[Decision](allowCap), deny: newLRU[Decision](denyCap)}
}

// GetOrRoute returns the cached decision for sni, or computes and stores it.
// The bool reports a cache hit.
func (c *RouteCache) GetOrRoute(sni string, route func() Decision) (Decision, bool) {
	if d, ok := c.allow.Get(sni); ok {
		return d, true
	}
	if d, ok := c.deny.Get(sni); ok {
		return d, true
	}
	d := route() // outside the locks; a concurrent miss just computes it twice
	if d.Allow {
		c.allow.Put(sni, d)
	} else {
		c.deny.Put(sni, d)
	}
	return d, false
}

// Len returns (allowed, denied) entry counts.
func (c *RouteCache) Len() (int, int) { return c.allow.Len(), c.deny.Len() }
