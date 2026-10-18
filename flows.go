package main

// The flow log: every connection from accept to close, for the console's
// Flow log page. A short connection is over before a state frame can show
// it; here it is not missed. While a page watches, each connection's opened,
// routed and closed events go to a broadcasting go-named-queue (drop-oldest,
// so a slow page never holds up the proxy). Every flowSnapshotInterval the
// page also gets the authoritative list of open connections, which repairs
// whatever a dropped event lost. The last flowHistory closed connections are
// kept, so a page opened later starts with them.

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"sync/atomic"
	"time"

	queue "github.com/wushilin/go-named-queue"
)

const (
	flowQueue            = "console.flows"
	flowQueueCapacity    = 4096 // events a slow page may lag behind; older ones are dropped
	flowHistory          = 2000 // closed connections kept for pages opened later
	flowSnapshotInterval = 5 * time.Second
	flowRecent           = 35 * time.Second // closed history a page gets unless it asks for all (it shows 30 s)
	flowBatch            = 512              // events per WebSocket message at most
	maxSnapshotFlows     = 5000             // open connections per snapshot; "truncated" says when there are more
)

// Flow results, once a connection has ended.
const (
	flowClosed   = "closed"   // relayed, then closed
	flowDenied   = "denied"   // a deny rule, or no rule
	flowFailed   = "failed"   // bad ClientHello, target unreachable, TLS failure...
	flowACME     = "acme"     // a TLS-ALPN-01 validation answered here
	flowRejected = "rejected" // turned away before its ClientHello was read
)

type flowView struct {
	ID uint64 `json:"id"`
	// Seq orders views of the same connection: a page keeps the one with the
	// highest, so a snapshot built just before an event can't undo it.
	Seq        uint64 `json:"seq"`
	Listener   string `json:"listener"`
	Src        string `json:"src"`
	Local      string `json:"local"`
	SNI        string `json:"sni"`
	Routed     bool   `json:"routed"` // the SNI is known (it may be "": no name sent)
	Dst        string `json:"dst,omitempty"`
	Peer       string `json:"peer,omitempty"`
	Rule       string `json:"rule,omitempty"` // the pattern that routed it
	RuleKey    string `json:"ruleKey,omitempty"`
	Terminated bool   `json:"terminated,omitempty"`
	Started    int64  `json:"started"`         // unix ms
	Ended      int64  `json:"ended,omitempty"` // unix ms; 0 while open
	BytesUp    int64  `json:"bytesUp"`
	BytesDown  int64  `json:"bytesDown"`
	Result     string `json:"result,omitempty"` // once ended: closed, denied, failed or acme
	Reason     string `json:"reason,omitempty"`
	flowHow
}

// flowHow is how a connection is handled, for the flow log's chips.
type flowHow struct {
	Via        string  `json:"via,omitempty"`        // the load balancer that sent a PROXY header
	ViaVersion int     `json:"viaVersion,omitempty"` // and its version
	TLS        string  `json:"tls,omitempty"`        // passthrough or terminated, once routed
	ClientTLS  string  `json:"clientTLS,omitempty"`  // terminated: the version spoken with the client
	ALPN       string  `json:"alpn,omitempty"`       // terminated: negotiated; passed through: offered
	Upstream   string  `json:"upstream,omitempty"`   // terminated: tls, tls-unverified or plain
	Resumed    bool    `json:"resumed,omitempty"`    // terminated: a resumed TLS session
	ProxyOut   int     `json:"proxyOut,omitempty"`   // PROXY header version sent to the target
	Relay      string  `json:"relay,omitempty"`      // splice or copy, once relaying
	ConnLimit  float64 `json:"connLimit,omitempty"`  // bytes/s per direction for this connection
	ShareLimit float64 `json:"shareLimit,omitempty"` // bytes/s per direction it shares with others
	Cached     bool    `json:"cached,omitempty"`     // routed from the route cache
}

type flowEvent struct {
	Type string   `json:"type"` // open, route, close
	Flow flowView `json:"flow"`
}

type flowLog struct {
	queues  *queue.QueueRegistry
	events  *queue.Sender[[]byte]
	viewers atomic.Int32 // pages watching; no event is built while zero

	// The last flowHistory closed connections, written without a lock: each
	// close takes the next slot with one atomic add and publishes its view
	// into it. Readers see each slot's latest view, whole.
	closed [flowHistory]atomic.Pointer[flowView]
	next   atomic.Uint64
}

func newFlowLog() *flowLog {
	f := &flowLog{queues: queue.NewRegistry()}
	if err := queue.CreateBroadcastingWithFullAction[[]byte](f.queues, flowQueue, flowQueueCapacity, queue.FullDropOldest); err != nil {
		panic(err) // a fresh registry cannot already hold the queue
	}
	f.events, _ = queue.AcquireSender[[]byte](f.queues, flowQueue)
	return f
}

var flowSeq atomic.Uint64

// view describes c as it is now.
func (c *ConnState) flow() flowView {
	c.mu.Lock()
	seq := flowSeq.Add(1) // under c.mu: views of c are numbered in the order they were taken
	v := flowView{ID: c.ID, Listener: c.Listener, Src: c.Src, Local: c.Local, SNI: c.SNI, Routed: c.routed,
		Dst: c.Dst, Peer: c.Peer, Rule: c.rulePattern, RuleKey: c.RuleKey, Terminated: c.Mode != "",
		Started: c.Start.UnixMilli(), Result: c.result, Reason: c.endReason, flowHow: c.how}
	c.mu.Unlock()
	switch relaying, spliced := c.relaying.Load(), c.spliced.Load(); {
	case relaying == 0:
	case spliced == relaying:
		v.Relay = "splice"
	case spliced == 0:
		v.Relay = "copy"
	default:
		v.Relay = "splice+copy" // one direction could not be spliced
	}
	v.Seq = seq
	v.BytesUp, v.BytesDown = c.BytesUp.Load(), c.BytesDown.Load()
	return v
}

// emit publishes one event, if a page is watching.
func (f *flowLog) emit(typ string, c *ConnState) {
	if f.viewers.Load() == 0 {
		return
	}
	f.publish(flowEvent{Type: typ, Flow: c.flow()})
}

func (f *flowLog) publish(ev flowEvent) {
	if data, err := json.Marshal(ev); err == nil {
		f.events.Send(data) // never blocks: drop-oldest
	}
}

// end records c as closed and tells the watching pages.
func (f *flowLog) end(c *ConnState) {
	v := c.flow()
	v.Ended = time.Now().UnixMilli()
	if v.Result == "" {
		v.Result = flowClosed
	}
	f.record(v)
}

// refused records a connection turned away before it was registered (a
// limit, a bad PROXY header): it opens and closes at once.
func (f *flowLog) refused(id uint64, listener string, start time.Time, src, local net.Addr, reason string) {
	now := time.Now().UnixMilli()
	f.record(flowView{ID: id, Seq: flowSeq.Add(1), Listener: listener, Src: src.String(), Local: local.String(),
		Started: start.UnixMilli(), Ended: now, Result: flowRejected, Reason: reason})
}

func (f *flowLog) record(v flowView) {
	f.closed[(f.next.Add(1)-1)%flowHistory].Store(&v)
	if f.viewers.Load() > 0 {
		f.publish(flowEvent{Type: "close", Flow: v})
	}
}

// closedSince returns the kept closed connections that ended at or after
// since (unix ms), oldest first.
func (f *flowLog) closedSince(since int64) []flowView {
	out := []flowView{}
	for i := range f.closed {
		if v := f.closed[i].Load(); v != nil && v.Ended >= since {
			out = append(out, *v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ended != out[j].Ended {
			return out[i].Ended < out[j].Ended
		}
		return out[i].Seq < out[j].Seq
	})
	return out
}

type flowSnapshot struct {
	Type      string     `json:"type"` // snapshot
	Now       int64      `json:"now"`
	Full      bool       `json:"full"` // the first one: closed holds the history asked for
	Active    []flowView `json:"active"`
	Truncated bool       `json:"truncated"` // more were open than are listed
	Closed    []flowView `json:"closed"`
}

// snapshot lists the open connections, and those closed since since.
func (s *Server) flowSnapshot(since int64, full bool) flowSnapshot {
	st := s.stats
	conns, truncated := st.connList(maxSnapshotFlows)
	snap := flowSnapshot{Type: "snapshot", Full: full, Active: make([]flowView, 0, len(conns)), Truncated: truncated}
	for _, c := range conns {
		snap.Active = append(snap.Active, c.flow())
	}
	snap.Closed = st.flows.closedSince(since)
	snap.Now = time.Now().UnixMilli()
	return snap
}

// flowSocket streams the flow log to one page until it leaves, signs out
// or its session expires.
func (c *Console) flowSocket(w http.ResponseWriter, r *http.Request) {
	ws, err := upgradeWebSocket(w, r)
	if err != nil {
		return
	}
	defer ws.Close()
	flows := c.srv.stats.flows
	// Subscribe before the first snapshot, so nothing falls between them.
	rx, err := queue.AcquireReceiver[[]byte](flows.queues, flowQueue)
	if err != nil {
		return
	}
	defer rx.Close()
	flows.viewers.Add(1)
	defer flows.viewers.Add(-1)

	// The page shows 30 s of closed connections unless "Show all closed" is
	// on; only then is the whole history worth sending.
	since := time.Now().Add(-flowRecent).UnixMilli()
	if r.URL.Query().Get("history") == "all" {
		since = 0
	}
	first := c.srv.flowSnapshot(since, true)
	data, err := json.Marshal(first)
	if err != nil || ws.writeFrame(wsOpText, data) != nil {
		return
	}
	done := make(chan struct{})
	defer close(done)
	gone := make(chan struct{})
	go func() {
		_ = ws.readLoop()
		close(gone)
	}()
	// Recv cannot be cancelled, so a watcher closes the receiver when the page
	// leaves, its session ends or a write fails. It also sends the snapshots.
	go func() {
		ping := time.NewTicker(wsPingInterval)
		check := time.NewTicker(time.Second)
		snap := time.NewTicker(flowSnapshotInterval)
		defer ping.Stop()
		defer check.Stop()
		defer snap.Stop()
		last := first.Now
		for {
			select {
			case <-gone:
			case <-done:
			case <-check.C:
				if c.session(r) != nil {
					continue
				}
				ws.writeFrame(wsOpClose, []byte{0x0F, 0xA0}) // 4000: signed out
			case <-ping.C:
				if ws.writeFrame(wsOpPing, nil) == nil {
					continue
				}
			case <-snap.C:
				// Overlap the previous snapshot by a second: a connection
				// closing while it was built is listed by one of them.
				s := c.srv.flowSnapshot(last-1000, false)
				last = s.Now
				if data, err := json.Marshal(s); err == nil && ws.writeFrame(wsOpText, data) == nil {
					continue
				}
			}
			rx.Close()
			ws.Close()
			return
		}
	}()
	var msg bytes.Buffer
	for {
		ev, err := rx.Recv()
		if err != nil {
			return
		}
		// Whatever else is waiting goes in the same message.
		msg.Reset()
		msg.WriteString(`{"type":"events","events":[`)
		msg.Write(ev)
		for n := 1; n < flowBatch; n++ {
			more, err := rx.TryRecv()
			if err != nil {
				break
			}
			msg.WriteByte(',')
			msg.Write(more)
		}
		msg.WriteString("]}")
		if ws.writeFrame(wsOpText, msg.Bytes()) != nil {
			return
		}
	}
}
