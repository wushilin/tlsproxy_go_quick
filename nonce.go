package main

// remember_nonce: loop detection. The proxy remembers, for nonceTTL, a hash
// of every ClientHello it forwards untouched. A ClientHello that comes in
// with one of those hashes is this proxy's own connection arriving back at
// itself: a name that resolves here, ${host} on a name pointing at this
// machine or at 127.0.0.1, a target that is another of its listeners. It is
// refused at once, instead of each hop opening the next until
// max_connections runs out.
//
// The whole message is hashed, so nothing depends on what a client puts in
// any field (an all-zero random is no exception): a refused connection sent
// byte for byte the same ClientHello as one forwarded seconds earlier. Real
// clients never do (each picks a fresh random); a replayed hello deserves no
// better. The hash is 64-bit maphash, several times faster than SHA-256,
// with a random per-process seed, so nobody can aim for a collision.
//
// Only passed-through connections are covered: a terminated one starts a
// new TLS session upstream, with a ClientHello crypto/tls makes.

import (
	"sync/atomic"
	"time"
)

// The cache is a fixed table of nonceSlots atomic words, never swept: the
// low nonceIndexBits of a hash pick its slot, which holds the other 44 bits
// and when it was stored: a stamp in nonceTick units that cycles through
// 1..nonceStampMask (about 18 hours), never 0, so 0 is always an empty slot. An entry counts for nonceTTL; a newer hash landing in the same
// slot evicts it sooner. One atomic store to remember, one load to check:
// nothing locks, nothing waits, nothing has to be cleaned up. A loop comes
// back within milliseconds, long before its slot is likely to be reused.
const (
	nonceIndexBits = 20
	nonceSlots     = 1 << nonceIndexBits // 1M hashes at most, 8 MiB
	nonceStampBits = 20
	nonceStampMask = 1<<nonceStampBits - 1
	nonceTick      = time.Second / 16
	nonceTTL       = 10 * time.Second
	nonceTTLTicks  = uint64(nonceTTL / nonceTick)
)

type nonceCache struct {
	slots []atomic.Uint64 // 0 = empty
	start time.Time       // stamps count from here
}

func newNonceCache() *nonceCache {
	return &nonceCache{slots: make([]atomic.Uint64, nonceSlots), start: time.Now()}
}

func (c *nonceCache) stamp(now time.Time) uint64 {
	return uint64(now.Sub(c.start)/nonceTick)%nonceStampMask + 1
}

// remember records the hash of a ClientHello about to be forwarded.
func (c *nonceCache) remember(digest uint64, now time.Time) {
	c.slots[digest&(nonceSlots-1)].Store(digest>>nonceIndexBits<<nonceStampBits | c.stamp(now))
}

// seen reports whether a ClientHello with this hash was forwarded within
// nonceTTL (and not evicted since).
func (c *nonceCache) seen(digest uint64, now time.Time) bool {
	v := c.slots[digest&(nonceSlots-1)].Load()
	stored := v & nonceStampMask
	if stored == 0 || v>>nonceStampBits != digest>>nonceIndexBits {
		return false // empty, or another hash
	}
	return (c.stamp(now)+nonceStampMask-stored)%nonceStampMask < nonceTTLTicks
}
