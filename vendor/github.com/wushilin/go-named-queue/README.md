# go-named-queue

Go implementation of the Rust `named_queue` crate's in-process named queue
model. Queues have a fixed positive capacity and a message type fixed at
creation. Multiple senders and receivers may share a queue; receivers compete
for messages.

```go
package main

import (
	"fmt"
	queue "github.com/wushilin/go-named-queue"
)

func main() {
	r := queue.NewRegistry()
	if err := queue.Create[string](r, "greetings", 16); err != nil {
		panic(err)
	}
	tx, _ := queue.AcquireSender[string](r, "greetings")
	rx, _ := queue.AcquireReceiver[string](r, "greetings")
	_ = tx.Send("hello")
	message, _ := rx.Recv()
	fmt.Println(message)
	_ = r.Shutdown("greetings")
}
```

`Create` creates a work-sharing queue: receivers compete, and each message is
delivered to one receiver. `CreateBroadcasting` creates a broadcast queue:
every receiver subscribed when a message is sent gets an independent delivery.
Receivers acquired later start at the current tail. A broadcast send blocks
when the bounded buffer is full until every subscribed receiver advances.
Use `CreateWithFullAction` or `CreateBroadcastingWithFullAction` to select what
happens when capacity is reached: `FullBlock` waits for space, `FullDropOldest`
evicts the oldest pending message and enqueues the new one, and `FullDropNewest`
silently discards the new message. Drop policies apply to `Send` and `TrySend`;
`TrySend` with `FullBlock` returns `ErrFull` instead of waiting.

```go
if err := queue.CreateBroadcasting[string](r, "events", 64); err != nil {
	panic(err)
}
tx, _ := queue.AcquireSender[string](r, "events")
a, _ := queue.AcquireReceiver[string](r, "events")
b, _ := queue.AcquireReceiver[string](r, "events")
_ = tx.Send("tick")
first, _ := a.Recv()
second, _ := b.Recv()
fmt.Println(first, second) // tick tick
a.Close()
b.Close()
```

`Send` and `Recv` block when the bounded queue is full or empty. `TrySend` and
`TryRecv` are nonblocking and return `ErrFull`/`ErrEmpty` when unavailable.

`Shutdown` closes a queue: sends (including ones blocked at that moment) fail
with `ErrClosed`, no new senders are issued, and shutting down again returns
`ErrClosed`. Existing receivers drain the buffered messages and then receive
`ErrClosed`. A shut-down work-sharing queue still admits new receivers while
messages remain; a shut-down broadcast queue admits none, since a new
subscription could never hold anything to drain. `Destroy` force-retires a
queue and discards buffered messages. `DestroyTake[T]` retires a matching typed
queue and returns its still-buffered messages.

Call `Close` on broadcast receivers when they are no longer needed so they no
longer hold messages in the bounded buffer (with `FullBlock`, a forgotten
receiver eventually blocks every sender). `Close` is idempotent, wakes a
blocked `Recv`, and afterwards the receiver reports `ErrClosed`. Use
`NewRegistry` to scope queues explicitly, or `DefaultRegistry` and the
`*Default` helpers for process-wide queues. A registry's zero value is also
usable; always pass a `*QueueRegistry`. Go's generic functions take the
registry as an argument because Go does not support generic methods.

## Differences from the Rust crate

- Send errors do not hand the unsent value back; the caller still owns the
  value passed to `Send`.
- A shut-down queue's name stays registered until the queue is drained *and*
  `Destroy` is called. Rust retires the entry automatically once the last
  receiver drains it; Go has no destructors to detect that.
- `Clone` on a broadcast receiver creates an independent subscriber. In Rust,
  clones share one subscription and compete.
- Broadcast queues default to `FullBlock`; the Rust default is `DropOldest`.
- A broadcast send blocked on a full subscriber fails with `ErrClosed` when
  the queue is shut down, whereas Rust lets the in-flight send complete.
- `DestroyTake` on a broadcast queue returns the still-buffered messages;
  Rust returns an empty list.
- There is no async or context-aware API; `Send`/`Recv` cannot be cancelled.

Run `go test -race ./...` for the test suite and `go test -bench . -benchmem`
for benchmarks.
