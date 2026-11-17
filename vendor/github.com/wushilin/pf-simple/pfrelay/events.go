package pfrelay

import "fmt"

// ConnID names one connection through the tunnel: the id the server gave
// it, the same on both ends of the tunnel. It is opaque; compare it, use it
// as a map key, print it with String. The zero ConnID names nothing.
type ConnID struct{ id string }

func (id ConnID) String() string { return id.id }

// MarshalText makes a ConnID marshal (to JSON and the like) as its string.
func (id ConnID) MarshalText() ([]byte, error) { return []byte(id.id), nil }

// Short is the start of the id, enough to tell connections apart in a log.
func (id ConnID) Short() string { return short(id.id) }

// Events are the handlers a Client calls as things happen; each one that
// is nil (the default) is not called. They are called synchronously from
// the goroutine where the event happened, so a handler should return
// quickly; it may call Client.Drop, Client.Conns and Client.Stats.
type Events struct {
	// OnServing: Listen, Serve or ServeOne registered with the server
	// (true), or lost that registration (false).
	OnServing func(up bool)
	// OnTunnel: Watch found the tunnel reachable (true) or not (false,
	// with why). Called with the first result and on every change.
	OnTunnel func(up bool, err error)
	// OnOpen: a connection was opened: dialed, accepted by Listen, or
	// carried by a forwarder (Serve, Connect, ServeOne, ConnectOne).
	OnOpen func(ConnInfo)
	// OnClose: a connection ended, exactly once for each OnOpen, with its
	// final figures. err is nil after a clean finish, and otherwise why it
	// failed (a *RemoteError when the far end or the server said why).
	OnClose func(info ConnInfo, err error)
	// OnRefuse: this side refused a connection the server offered it,
	// telling the far end reason: the backlog was full, the target could
	// not be reached, or ServeOne already carries its one connection. A
	// refused connection is never opened.
	OnRefuse func(id ConnID, reason string)
}

// opened records a new connection and reports it.
func (c *Client) opened(rec *connRecord) {
	if c.Events.OnOpen != nil {
		c.Events.OnOpen(rec.info())
	}
}

// closed retires rec, once, and reports it.
func (c *Client) closed(rec *connRecord, err error) {
	if r := rec.dropped.Load(); r != nil {
		err = &DroppedError{Reason: *r} // a dropped connection failed, however it then ended
	}
	if !c.reg.finish(rec, err != nil) {
		return
	}
	if c.Events.OnClose != nil {
		c.Events.OnClose(rec.info(), err)
	}
}

func (c *Client) refused(id, reason string) {
	if c.Events.OnRefuse != nil {
		c.Events.OnRefuse(ConnID{id}, reason)
	}
}

func (c *Client) serving(up bool) {
	if c.Events.OnServing != nil {
		c.Events.OnServing(up)
	}
}

// Drop ends the open connection id at once and tells the far end reason,
// as Conn.Fail does. It reports whether such a connection was open.
func (c *Client) Drop(id ConnID, reason string) bool {
	c.reg.mu.Lock()
	var rec *connRecord
	for r := range c.reg.live {
		if r.id == id {
			rec = r
			break
		}
	}
	c.reg.mu.Unlock()
	if rec == nil {
		return false
	}
	rec.dropped.Store(&reason)
	rec.stream.Fail(reason)
	return true
}

// DroppedError is how a connection ended that this side dropped, with Fail
// or Drop.
type DroppedError struct{ Reason string }

func (e *DroppedError) Error() string { return fmt.Sprintf("dropped by this side: %s", e.Reason) }
