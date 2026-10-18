package main

import (
	"sync"
	"sync/atomic"
)

// clock is a capped map from string to V for the serving path: a hit takes
// no lock (a sync.Map read and an atomic "recently used" flag), so any number
// of connections can look up the same names at once. It evicts with the
// CLOCK algorithm, an approximation of least-recently-used: a hand sweeps the
// slots, clearing the flag of each recently used entry and evicting the first
// one that has not been used since the hand last passed.
//
// Inserting takes a mutex, but only with TryLock: if another insert holds it,
// the value is simply not cached this time (the caller computed it anyway).
// Nothing on the serving path ever waits for it.
type clock[V any] struct {
	index sync.Map // string -> *clockEntry[V]
	cap   int
	n     atomic.Int64

	insertMu sync.Mutex // guards slots and hand
	slots    []*clockEntry[V]
	hand     int
}

type clockEntry[V any] struct {
	key  string
	val  atomic.Pointer[V]
	used atomic.Bool
}

func newClock[V any](capacity int) *clock[V] {
	c := &clock[V]{cap: capacity}
	c.index.Load("") // set the map up now, not under the first connections (see syncMap.init)
	return c
}

func (c *clock[V]) Get(key string) (V, bool) {
	if e, ok := c.index.Load(key); ok {
		e := e.(*clockEntry[V])
		if !e.used.Load() { // write the shared flag only when it changes
			e.used.Store(true)
		}
		return *e.val.Load(), true
	}
	var zero V
	return zero, false
}

// Put stores val under key. Replacing a cached value takes no lock; adding a
// new key is skipped when another insert is in progress.
func (c *clock[V]) Put(key string, val V) {
	if c.cap <= 0 {
		return
	}
	if e, ok := c.index.Load(key); ok {
		e.(*clockEntry[V]).val.Store(&val)
		return
	}
	if !c.insertMu.TryLock() {
		return
	}
	defer c.insertMu.Unlock()
	if e, ok := c.index.Load(key); ok { // added while we were getting here
		e.(*clockEntry[V]).val.Store(&val)
		return
	}
	e := &clockEntry[V]{key: key}
	e.val.Store(&val)
	if len(c.slots) < c.cap {
		c.slots = append(c.slots, e)
		c.n.Add(1)
	} else {
		for { // second chance: skip (and clear) recently used entries
			old := c.slots[c.hand]
			if old.used.Load() {
				old.used.Store(false)
				c.hand = (c.hand + 1) % c.cap
				continue
			}
			c.index.Delete(old.key)
			c.slots[c.hand] = e
			c.hand = (c.hand + 1) % c.cap
			break
		}
	}
	c.index.Store(key, e)
}

func (c *clock[V]) Len() int { return int(c.n.Load()) }

func (c *clock[V]) Contains(key string) bool {
	_, ok := c.index.Load(key)
	return ok
}

// RouteCache caches routing decisions by lowercased SNI. Allowed and denied
// names live in separate LRUs with separate caps: allowed names are few and
// concentrated, denied names can be many and random, so a flood of junk names
// can only evict other junk. Routing errors count as denials.
type RouteCache struct {
	allow, deny *clock[Decision]
}

func NewRouteCache(allowCap, denyCap int) *RouteCache {
	return &RouteCache{allow: newClock[Decision](allowCap), deny: newClock[Decision](denyCap)}
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
	d := route() // no lock held; a concurrent miss just computes it twice
	if d.Allow {
		c.allow.Put(sni, d)
	} else {
		c.deny.Put(sni, d)
	}
	return d, false
}

// Len returns (allowed, denied) entry counts.
func (c *RouteCache) Len() (int, int) { return c.allow.Len(), c.deny.Len() }
