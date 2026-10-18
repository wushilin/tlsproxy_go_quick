// Package namedqueue provides named, typed, bounded in-process queues.
// Work-sharing queues deliver each message to one of the competing receivers;
// broadcast queues deliver each message to every subscribed receiver.
package namedqueue

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
)

var (
	ErrExists            = errors.New("namedqueue: queue already exists")
	ErrNotFound          = errors.New("namedqueue: queue not found")
	ErrTypeMismatch      = errors.New("namedqueue: message type mismatch")
	ErrClosed            = errors.New("namedqueue: queue is closed")
	ErrFull              = errors.New("namedqueue: queue is full")
	ErrEmpty             = errors.New("namedqueue: queue is empty")
	ErrInvalidCapacity   = errors.New("namedqueue: capacity must be positive")
	ErrInvalidFullAction = errors.New("namedqueue: invalid full action")
)

// State is a point-in-time queue lifecycle snapshot.
type State struct {
	Open    bool
	Pending int
}

// FullAction selects what Send does when a bounded queue is full.
type FullAction uint8

const (
	// FullBlock waits until receivers make space.
	FullBlock FullAction = iota
	// FullDropOldest evicts the oldest pending message and enqueues the new one.
	FullDropOldest
	// FullDropNewest discards the message being sent and returns success.
	FullDropNewest
)

func (a FullAction) valid() bool { return a == FullBlock || a == FullDropOldest || a == FullDropNewest }

type queue interface {
	typeOf() reflect.Type
	// shutdown reports false when the queue was already shut down.
	shutdown() bool
	destroy() []any
	state() State
}

type registryData struct {
	mu     sync.RWMutex
	queues map[string]queue
}

// QueueRegistry owns named queues. Its zero value is ready to use; handles made
// with Clone share the same registry. Always pass a *QueueRegistry around; a
// QueueRegistry value must not be copied.
type QueueRegistry struct{ data atomic.Pointer[registryData] }

func newRegistryData() *registryData { return &registryData{queues: make(map[string]queue)} }

func NewRegistry() *QueueRegistry {
	r := &QueueRegistry{}
	r.data.Store(newRegistryData())
	return r
}

func (r *QueueRegistry) dataRef() *registryData {
	if r == nil {
		return nil
	}
	if d := r.data.Load(); d != nil {
		return d
	}
	// First use of a zero value: whichever goroutine wins the swap installs
	// the data; the others adopt it.
	r.data.CompareAndSwap(nil, newRegistryData())
	return r.data.Load()
}

// Clone returns another registry handle sharing the same queues.
func (r *QueueRegistry) Clone() *QueueRegistry {
	c := &QueueRegistry{}
	c.data.Store(r.dataRef())
	return c
}

// ring is a fixed-capacity FIFO. Slots are zeroed as they are popped so the
// buffer never retains references to delivered messages.
type ring[T any] struct {
	buf        []T
	head, size int
}

func newRing[T any](capacity int) ring[T] { return ring[T]{buf: make([]T, capacity)} }
func (q *ring[T]) len() int               { return q.size }
func (q *ring[T]) full() bool             { return q.size == len(q.buf) }
func (q *ring[T]) at(i int) T             { return q.buf[(q.head+i)%len(q.buf)] }
func (q *ring[T]) push(v T) {
	q.buf[(q.head+q.size)%len(q.buf)] = v
	q.size++
}
func (q *ring[T]) pop() T {
	v := q.buf[q.head]
	var z T
	q.buf[q.head] = z
	q.head = (q.head + 1) % len(q.buf)
	q.size--
	return v
}

// drain pops everything, returning it in FIFO order.
func (q *ring[T]) drain() []T {
	out := make([]T, 0, q.size)
	for q.size > 0 {
		out = append(out, q.pop())
	}
	return out
}

type channel[T any] struct {
	mu                sync.Mutex
	canSend, canRecv  *sync.Cond
	items             ring[T]
	closed, destroyed bool
	fullAction        FullAction
}

// broadcastChannel retains each value until every receiver that was subscribed
// at send time has consumed it. New receivers start at the current tail.
type broadcastItem[T any] struct {
	seq   uint64
	value T
}

// A subscriber's cursor is only read or written under the channel mutex.
type broadcastSubscriber struct {
	next   uint64
	closed bool
}
type broadcastChannel[T any] struct {
	mu                sync.Mutex
	canSend, canRecv  *sync.Cond
	items             ring[broadcastItem[T]]
	next              uint64
	subs              map[*broadcastSubscriber]struct{}
	closed, destroyed bool
	fullAction        FullAction
}

func newBroadcastChannel[T any](capacity int, action FullAction) *broadcastChannel[T] {
	c := &broadcastChannel[T]{fullAction: action, items: newRing[broadcastItem[T]](capacity), subs: make(map[*broadcastSubscriber]struct{})}
	c.canSend, c.canRecv = sync.NewCond(&c.mu), sync.NewCond(&c.mu)
	return c
}
func (c *broadcastChannel[T]) typeOf() reflect.Type { return reflect.TypeOf((*T)(nil)).Elem() }
func (c *broadcastChannel[T]) shutdown() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.closed = true
	c.canSend.Broadcast()
	c.canRecv.Broadcast()
	return true
}
func (c *broadcastChannel[T]) state() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return State{Open: !c.closed && !c.destroyed, Pending: c.items.len()}
}
func (c *broadcastChannel[T]) destroy() []any {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed, c.destroyed = true, true
	items := c.items.drain()
	out := make([]any, len(items))
	for i, item := range items {
		out[i] = item.value
	}
	c.canSend.Broadcast()
	c.canRecv.Broadcast()
	return out
}

// subscribe registers a cursor at the current tail. A shut-down queue admits
// no new subscribers: a fresh subscription could never hold anything to drain.
func (c *broadcastChannel[T]) subscribe() (*broadcastSubscriber, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.destroyed {
		return nil, ErrClosed
	}
	s := &broadcastSubscriber{next: c.next}
	c.subs[s] = struct{}{}
	return s, nil
}

// unsubscribe is idempotent and wakes any Recv blocked on this subscriber.
func (c *broadcastChannel[T]) unsubscribe(s *broadcastSubscriber) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	delete(c.subs, s)
	c.cleanup()
	c.canRecv.Broadcast()
}

// take pops the next message for s. Caller holds c.mu and has established
// that s is live and lagging, so its cursor is inside the buffer.
func (c *broadcastChannel[T]) take(s *broadcastSubscriber) T {
	v := c.items.at(int(s.next - c.items.at(0).seq)).value
	s.next++
	c.cleanup()
	return v
}

// cleanup drops messages every live subscriber has passed. Caller holds c.mu.
func (c *broadcastChannel[T]) cleanup() {
	min := c.next
	for s := range c.subs {
		if s.next < min {
			min = s.next
		}
	}
	for c.items.len() > 0 && c.items.at(0).seq < min {
		c.items.pop()
	}
	c.canSend.Broadcast()
}

// evictOldest drops the oldest message and moves any subscriber still
// pointing at it past it. Caller holds c.mu and the buffer is non-empty.
func (c *broadcastChannel[T]) evictOldest() {
	oldest := c.items.pop().seq
	for s := range c.subs {
		if s.next <= oldest {
			s.next = oldest + 1
		}
	}
}

// publish appends v at the tail. Caller holds c.mu and the buffer has room.
func (c *broadcastChannel[T]) publish(v T) {
	c.items.push(broadcastItem[T]{seq: c.next, value: v})
	c.next++
	c.canRecv.Broadcast()
}
func (c *broadcastChannel[T]) send(v T) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.subs) == 0 {
		if c.closed || c.destroyed {
			return ErrClosed
		}
		return nil
	}
	for c.items.full() && !c.closed && !c.destroyed {
		switch c.fullAction {
		case FullDropNewest:
			return nil
		case FullDropOldest:
			c.evictOldest()
		default:
			c.canSend.Wait()
		}
	}
	if c.closed || c.destroyed {
		return ErrClosed
	}
	c.publish(v)
	return nil
}
func (c *broadcastChannel[T]) trySend(v T) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.destroyed {
		return ErrClosed
	}
	if len(c.subs) == 0 {
		return nil
	}
	if c.items.full() {
		switch c.fullAction {
		case FullDropNewest:
			return nil
		case FullDropOldest:
			c.evictOldest()
		default:
			return ErrFull
		}
	}
	c.publish(v)
	return nil
}
func (c *broadcastChannel[T]) recv(s *broadcastSubscriber) (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for s.next == c.next && !s.closed && !c.closed && !c.destroyed {
		c.canRecv.Wait()
	}
	if s.closed || c.destroyed || s.next == c.next {
		var z T
		return z, ErrClosed
	}
	return c.take(s), nil
}
func (c *broadcastChannel[T]) tryRecv(s *broadcastSubscriber) (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s.closed || c.destroyed {
		var z T
		return z, ErrClosed
	}
	if s.next == c.next {
		var z T
		if c.closed {
			return z, ErrClosed
		}
		return z, ErrEmpty
	}
	return c.take(s), nil
}

func newChannel[T any](capacity int, action FullAction) *channel[T] {
	c := &channel[T]{fullAction: action, items: newRing[T](capacity)}
	c.canSend, c.canRecv = sync.NewCond(&c.mu), sync.NewCond(&c.mu)
	return c
}
func (c *channel[T]) typeOf() reflect.Type { return reflect.TypeOf((*T)(nil)).Elem() }
func (c *channel[T]) shutdown() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.closed = true
	c.canSend.Broadcast()
	c.canRecv.Broadcast()
	return true
}
func (c *channel[T]) state() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return State{Open: !c.closed && !c.destroyed, Pending: c.items.len()}
}
func (c *channel[T]) destroy() []any {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.destroyed, c.closed = true, true
	items := c.items.drain()
	out := make([]any, len(items))
	for i, v := range items {
		out[i] = v
	}
	c.canSend.Broadcast()
	c.canRecv.Broadcast()
	return out
}
func (c *channel[T]) send(v T) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.items.full() && !c.closed && !c.destroyed {
		switch c.fullAction {
		case FullDropNewest:
			return nil
		case FullDropOldest:
			c.items.pop()
		default:
			c.canSend.Wait()
		}
	}
	if c.closed || c.destroyed {
		return ErrClosed
	}
	c.items.push(v)
	c.canRecv.Signal()
	return nil
}
func (c *channel[T]) trySend(v T) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.destroyed {
		return ErrClosed
	}
	if c.items.full() {
		switch c.fullAction {
		case FullDropNewest:
			return nil
		case FullDropOldest:
			c.items.pop()
		default:
			return ErrFull
		}
	}
	c.items.push(v)
	c.canRecv.Signal()
	return nil
}
func (c *channel[T]) recv() (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.items.len() == 0 && !c.closed && !c.destroyed {
		c.canRecv.Wait()
	}
	if c.destroyed || c.items.len() == 0 {
		var z T
		return z, ErrClosed
	}
	v := c.items.pop()
	c.canSend.Signal()
	return v, nil
}
func (c *channel[T]) tryRecv() (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.items.len() == 0 {
		var z T
		if c.closed || c.destroyed {
			return z, ErrClosed
		}
		return z, ErrEmpty
	}
	v := c.items.pop()
	c.canSend.Signal()
	return v, nil
}

func (r *QueueRegistry) get(name string, typ reflect.Type) (queue, error) {
	d := r.dataRef()
	if d == nil {
		return nil, ErrNotFound
	}
	d.mu.RLock()
	q, ok := d.queues[name]
	d.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	if q.typeOf() != typ {
		return nil, fmt.Errorf("%w: queue %q contains %v, requested %v", ErrTypeMismatch, name, q.typeOf(), typ)
	}
	return q, nil
}

// Create registers a bounded queue. Capacity must be positive.
func Create[T any](r *QueueRegistry, name string, capacity int) error {
	return CreateWithFullAction[T](r, name, capacity, FullBlock)
}

// CreateWithFullAction registers a bounded work-sharing queue with a full policy.
func CreateWithFullAction[T any](r *QueueRegistry, name string, capacity int, action FullAction) error {
	if capacity <= 0 {
		return ErrInvalidCapacity
	}
	if !action.valid() {
		return ErrInvalidFullAction
	}
	d := r.dataRef()
	if d == nil {
		return ErrNotFound
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.queues[name]; ok {
		return ErrExists
	}
	d.queues[name] = newChannel[T](capacity, action)
	return nil
}

// CreateBroadcasting registers a bounded queue where every subscribed receiver
// gets each message independently.
func CreateBroadcasting[T any](r *QueueRegistry, name string, capacity int) error {
	return CreateBroadcastingWithFullAction[T](r, name, capacity, FullBlock)
}

// CreateBroadcastingWithFullAction registers a broadcast queue with a full policy.
func CreateBroadcastingWithFullAction[T any](r *QueueRegistry, name string, capacity int, action FullAction) error {
	if capacity <= 0 {
		return ErrInvalidCapacity
	}
	if !action.valid() {
		return ErrInvalidFullAction
	}
	d := r.dataRef()
	if d == nil {
		return ErrNotFound
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.queues[name]; ok {
		return ErrExists
	}
	d.queues[name] = newBroadcastChannel[T](capacity, action)
	return nil
}

// AcquireSender returns a producer handle for a registered queue. A shut-down
// queue issues no new senders.
func AcquireSender[T any](r *QueueRegistry, name string) (*Sender[T], error) {
	q, e := r.get(name, reflect.TypeOf((*T)(nil)).Elem())
	if e != nil {
		return nil, e
	}
	if !q.state().Open {
		return nil, ErrClosed
	}
	switch c := q.(type) {
	case *channel[T]:
		return &Sender[T]{sendFn: c.send, trySendFn: c.trySend}, nil
	case *broadcastChannel[T]:
		return &Sender[T]{sendFn: c.send, trySendFn: c.trySend}, nil
	default:
		return nil, ErrTypeMismatch
	}
}

// AcquireReceiver returns a consumer handle for a registered queue. A shut-down
// work-sharing queue still admits receivers while messages remain to be
// drained; a shut-down broadcast queue admits none.
func AcquireReceiver[T any](r *QueueRegistry, name string) (*Receiver[T], error) {
	q, e := r.get(name, reflect.TypeOf((*T)(nil)).Elem())
	if e != nil {
		return nil, e
	}
	switch c := q.(type) {
	case *channel[T]:
		if st := c.state(); !st.Open && st.Pending == 0 {
			return nil, ErrClosed
		}
		return makeQueueReceiver(c), nil
	case *broadcastChannel[T]:
		sub, err := c.subscribe()
		if err != nil {
			return nil, err
		}
		return makeBroadcastReceiver(c, sub), nil
	default:
		return nil, ErrTypeMismatch
	}
}

func makeQueueReceiver[T any](c *channel[T]) *Receiver[T] {
	return &Receiver[T]{
		recvFn:    c.recv,
		tryRecvFn: c.tryRecv,
		cloneFn:   func() *Receiver[T] { return makeQueueReceiver(c) },
	}
}

func makeBroadcastReceiver[T any](c *broadcastChannel[T], sub *broadcastSubscriber) *Receiver[T] {
	return &Receiver[T]{
		recvFn:    func() (T, error) { return c.recv(sub) },
		tryRecvFn: func() (T, error) { return c.tryRecv(sub) },
		closeFn:   func() { c.unsubscribe(sub) },
		cloneFn: func() *Receiver[T] {
			s, err := c.subscribe()
			if err != nil {
				// The queue shut down in the meantime: hand back a receiver
				// that reports ErrClosed rather than failing the clone.
				s = &broadcastSubscriber{closed: true}
			}
			return makeBroadcastReceiver(c, s)
		},
	}
}

// Shutdown rejects future sends and allows receivers to drain pending messages.
// Shutting down a queue that is already shut down returns ErrClosed.
func (r *QueueRegistry) Shutdown(name string) error {
	d := r.dataRef()
	if d == nil {
		return ErrNotFound
	}
	d.mu.RLock()
	q, ok := d.queues[name]
	d.mu.RUnlock()
	if !ok {
		return ErrNotFound
	}
	if !q.shutdown() {
		return ErrClosed
	}
	return nil
}

// State returns the queue's open/closed state and number of pending messages.
func (r *QueueRegistry) State(name string) (State, error) {
	d := r.dataRef()
	if d == nil {
		return State{}, ErrNotFound
	}
	d.mu.RLock()
	q, ok := d.queues[name]
	d.mu.RUnlock()
	if !ok {
		return State{}, ErrNotFound
	}
	return q.state(), nil
}

// Destroy force-retires a queue and discards pending messages.
func (r *QueueRegistry) Destroy(name string) error {
	d := r.dataRef()
	if d == nil {
		return ErrNotFound
	}
	d.mu.Lock()
	q, ok := d.queues[name]
	if ok {
		delete(d.queues, name)
	}
	d.mu.Unlock()
	if !ok {
		return ErrNotFound
	}
	q.destroy()
	return nil
}

// DestroyTake force-retires a queue, returning all still-pending messages.
func DestroyTake[T any](r *QueueRegistry, name string) ([]T, error) {
	d := r.dataRef()
	if d == nil {
		return nil, ErrNotFound
	}
	d.mu.Lock()
	q, ok := d.queues[name]
	if !ok {
		d.mu.Unlock()
		return nil, ErrNotFound
	}
	if q.typeOf() != reflect.TypeOf((*T)(nil)).Elem() {
		d.mu.Unlock()
		return nil, ErrTypeMismatch
	}
	delete(d.queues, name)
	d.mu.Unlock()
	raw := q.destroy()
	out := make([]T, len(raw))
	for i, v := range raw {
		out[i] = v.(T)
	}
	return out, nil
}

// Sender is a producer handle. Copies of a sender share the same queue.
type Sender[T any] struct {
	sendFn    func(T) error
	trySendFn func(T) error
}

func (s *Sender[T]) Clone() *Sender[T] { return &Sender[T]{sendFn: s.sendFn, trySendFn: s.trySendFn} }
func (s *Sender[T]) Send(v T) error    { return s.sendFn(v) }
func (s *Sender[T]) TrySend(v T) error { return s.trySendFn(v) }

// Receiver is a consumer handle. Copies compete for messages.
type Receiver[T any] struct {
	recvFn    func() (T, error)
	tryRecvFn func() (T, error)
	cloneFn   func() *Receiver[T]
	closeFn   func()
}

func (r *Receiver[T]) Clone() *Receiver[T] { return r.cloneFn() }
func (r *Receiver[T]) Recv() (T, error)    { return r.recvFn() }
func (r *Receiver[T]) TryRecv() (T, error) { return r.tryRecvFn() }

// Close unsubscribes this receiver. Close broadcast receivers when they are no longer needed.
func (r *Receiver[T]) Close() {
	if r.closeFn != nil {
		r.closeFn()
	}
}

var defaultRegistry = NewRegistry()

func DefaultRegistry() *QueueRegistry { return defaultRegistry }
func CreateDefault[T any](name string, capacity int) error {
	return Create[T](defaultRegistry, name, capacity)
}
func CreateDefaultWithFullAction[T any](name string, capacity int, action FullAction) error {
	return CreateWithFullAction[T](defaultRegistry, name, capacity, action)
}
func CreateBroadcastingDefault[T any](name string, capacity int) error {
	return CreateBroadcasting[T](defaultRegistry, name, capacity)
}
func CreateBroadcastingDefaultWithFullAction[T any](name string, capacity int, action FullAction) error {
	return CreateBroadcastingWithFullAction[T](defaultRegistry, name, capacity, action)
}
func AcquireDefaultSender[T any](name string) (*Sender[T], error) {
	return AcquireSender[T](defaultRegistry, name)
}
func AcquireDefaultReceiver[T any](name string) (*Receiver[T], error) {
	return AcquireReceiver[T](defaultRegistry, name)
}
func Shutdown(name string) error { return defaultRegistry.Shutdown(name) }
func Destroy(name string) error  { return defaultRegistry.Destroy(name) }
func DestroyTakeDefault[T any](name string) ([]T, error) {
	return DestroyTake[T](defaultRegistry, name)
}
func QueueState(name string) (State, error) { return defaultRegistry.State(name) }
