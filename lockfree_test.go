package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func TestRingOrderAndBounds(t *testing.T) {
	r := newRing[int](3) // rounds up to 4
	if r.Cap() != 4 {
		t.Fatal(r.Cap())
	}
	for i := range 4 {
		if !r.TryPush(i) {
			t.Fatal("push", i)
		}
	}
	if r.TryPush(9) {
		t.Fatal("pushed into a full ring")
	}
	for i := range 4 {
		if v, ok := r.TryPop(); !ok || v != i {
			t.Fatal("pop", i, v, ok)
		}
	}
	if _, ok := r.TryPop(); ok {
		t.Fatal("popped from an empty ring")
	}
}

// Many producers and consumers: every item comes out exactly once.
func TestRingConcurrent(t *testing.T) {
	r := newRing[int](64)
	const producers, each = 8, 20000
	var seen [producers * each]atomic.Int32
	var wg sync.WaitGroup
	var popped atomic.Int64
	for p := range producers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				for !r.TryPush(p*each + i) {
				}
			}
		}()
	}
	done := make(chan struct{})
	var cwg sync.WaitGroup
	for range 4 {
		cwg.Add(1)
		go func() {
			defer cwg.Done()
			for {
				if v, ok := r.TryPop(); ok {
					seen[v].Add(1)
					popped.Add(1)
					continue
				}
				select {
				case <-done:
					if r.Len() == 0 {
						return
					}
				default:
				}
			}
		}()
	}
	wg.Wait()
	close(done)
	cwg.Wait()
	if popped.Load() != producers*each {
		t.Fatalf("popped %d of %d", popped.Load(), producers*each)
	}
	for i := range seen {
		if seen[i].Load() != 1 {
			t.Fatalf("item %d seen %d times", i, seen[i].Load())
		}
	}
}

// The connection table under churn: every connection is found while open,
// gone once removed, and the count ends at zero.
func TestConnTableConcurrent(t *testing.T) {
	var tab connTable
	var next atomic.Uint64
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 2000 {
				c := &ConnState{ID: next.Add(1)}
				slot := tab.add(c)
				if got, ok := tab.Load(c.ID); !ok || got != c {
					t.Error("an added connection is not found")
					return
				}
				tab.remove(slot)
			}
		}()
	}
	// Readers scan while it churns.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				tab.Range(func(*ConnState) bool { return true })
			}
		}
	}()
	wg.Wait()
	close(stop)
	if n := tab.Len(); n != 0 {
		t.Fatalf("%d left", n)
	}
	found := 0
	tab.Range(func(*ConnState) bool { found++; return true })
	if found != 0 {
		t.Fatalf("%d slots still taken", found)
	}
}

// A clock cache under concurrent hits and inserts stays within its cap.
func TestClockCacheConcurrent(t *testing.T) {
	c := newClock[int](64)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 5000 {
				k := string(rune('a' + (g*i)%200))
				if v, ok := c.Get(k); ok && v != len(k) {
					t.Error("wrong value")
					return
				}
				c.Put(k, len(k))
			}
		}()
	}
	wg.Wait()
	if c.Len() > 64 {
		t.Fatalf("%d entries in a cache of 64", c.Len())
	}
}

// The host table: one entry per name however many connections race for it,
// and names beyond maxHostStats share "(other)".
func TestHostTable(t *testing.T) {
	tab := newHostTable()
	var wg sync.WaitGroup
	got := make([]*HostStats, 16)
	for g := range got {
		wg.Add(1)
		go func() { defer wg.Done(); got[g] = tab.get("same.example") }()
	}
	wg.Wait()
	for _, h := range got {
		if h != got[0] {
			t.Fatal("racing first connections got different counters for one name")
		}
	}
	for i := range maxHostStats + 100 {
		tab.get(fmt.Sprintf("n%d.example", i))
	}
	if other := tab.get("one-more.example"); other != tab.get("(other)") || tab.Len() > maxHostStats+1 {
		t.Fatalf("over the cap: len %d", tab.Len())
	}
	if tab.get("same.example") != got[0] {
		t.Fatal("a known name must keep its counter after the cap is reached")
	}
}
