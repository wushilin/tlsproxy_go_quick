package main

// The console's rule manager: a live state frame pushed over a WebSocket
// (one broadcasting go-named-queue, as in pf-simple), and rule edits that
// rewrite one [[host]] block of the config file in place, comments and all.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	queue "github.com/wushilin/go-named-queue"
)

const (
	pushInterval       = 400 * time.Millisecond // how often the state is checked for changes
	stateQueue         = "console.state"
	stateQueueCapacity = 8 // frames a slow tab may lag behind; older ones are dropped
	wsPingInterval     = 30 * time.Second
	maxFrameConns      = 500 // connections listed per rule in a frame; connCount is the true number
	reloadWait         = 5 * time.Second
)

// ---------------------------------------------------------------- state frames

type fileView struct {
	Path     string `json:"path"`
	Hash     string `json:"hash"`
	Mtime    string `json:"mtime"`
	Editable bool   `json:"editable"`
	Error    string `json:"error,omitempty"`
}

type connView struct {
	ID            uint64 `json:"id"`
	Started       int64  `json:"started"` // unix ms
	Src           string `json:"src"`
	Local         string `json:"local"`
	UpstreamLocal string `json:"upstreamLocal"`
	Peer          string `json:"peer"`
	SNI           string `json:"sni"`
	Dst           string `json:"dst"`
	Mode          string `json:"mode"`
	Terminated    bool   `json:"terminated"`
	BytesUp       int64  `json:"bytesUp"`
	BytesDown     int64  `json:"bytesDown"`
	CToS          string `json:"cToS"`
	SToC          string `json:"sToC"`
	LastActivity  int64  `json:"lastActivity"` // unix ms
	Stopping      bool   `json:"stopping"`
}

type ruleView struct {
	Listener     string            `json:"listener"`
	Line         int               `json:"line"` // 0: not in the file (deleted while connections remain)
	Key          string            `json:"key"`
	Pattern      string            `json:"pattern"`
	Kind         string            `json:"kind"`
	Allow        bool              `json:"allow"`
	Target       string            `json:"target"`
	Terminates   bool              `json:"terminates"`
	Cert         string            `json:"cert"`
	Proxy        bool              `json:"proxy"`
	ProxyVersion int               `json:"proxyVersion"`
	AggSpeed     float64           `json:"aggSpeed"`
	ConnSpeed    float64           `json:"connSpeed"`
	Stopped      bool              `json:"stopped"`
	Running      bool              `json:"running"` // in the configuration the proxy is running
	Values       map[string]string `json:"values"`
	Active       int64             `json:"active"`
	Total        int64             `json:"total"`
	BytesUp      int64             `json:"bytesUp"`
	BytesDown    int64             `json:"bytesDown"`
	ConnCount    int               `json:"connCount"`
	Connections  []connView        `json:"connections"`
}

type listenerView struct {
	Name              string            `json:"name"`
	Line              int               `json:"line"` // 0: the implicit listener made from [global]
	Implicit          bool              `json:"implicit"`
	Removed           bool              `json:"removed,omitempty"`  // gone from the file; its connections remain
	Redirect          bool              `json:"redirect,omitempty"` // the http_to_https_redirect listener: Start/Stop only
	Bind              string            `json:"bind"`
	Port              int               `json:"port"`
	Addrs             []string          `json:"addrs"` // actually open
	Running           bool              `json:"running"`
	Stopped           bool              `json:"stopped"`
	Error             string            `json:"error,omitempty"`
	Values            map[string]string `json:"values"`
	ProxyProtocolFrom string            `json:"proxyProtocolFrom"`
	MaxConnections    int               `json:"maxConnections"`
	HandshakeTimeout  *int              `json:"handshakeTimeout"` // seconds; null = [global]
	IdleTimeout       *int              `json:"idleTimeout"`
	HalfCloseTimeout  *int              `json:"halfCloseTimeout"`
	AggSpeed          float64           `json:"aggSpeed"`
	ConnSpeed         float64           `json:"connSpeed"`
	Active            int64             `json:"active"`
	Accepted          int64             `json:"accepted"`
	Rejected          int64             `json:"rejected"`
	BytesUp           int64             `json:"bytesUp"`
	BytesDown         int64             `json:"bytesDown"`
	Rules             []ruleView        `json:"rules"`
}

type statusView struct {
	Active         int64 `json:"active"`
	Accepted       int64 `json:"accepted"`
	Completed      int64 `json:"completed"`
	Denied         int64 `json:"denied"`
	Failed         int64 `json:"failed"`
	Rejected       int64 `json:"rejected"`
	MaxConnections int   `json:"maxConnections"`
	BytesUp        int64 `json:"bytesUp"`
	BytesDown      int64 `json:"bytesDown"`
}

type consoleState struct {
	Host      string         `json:"host"`
	Now       int64          `json:"now"`
	Started   int64          `json:"started"`
	Status    statusView     `json:"status"`
	File      fileView       `json:"file"`
	Listeners []listenerView `json:"listeners"`
}

// parsedFile is the config file as last read, re-read only when it changes.
type parsedFile struct {
	mtime  time.Time
	size   int64
	view   fileView
	text   string
	cfg    *Config // nil when the file does not parse
	lines  []string
	blocks map[int]block // header line -> [[host]] or [[listener]] block
}

type ruleState struct {
	queues *queue.QueueRegistry
	frames *queue.Sender[[]byte]
	mu     sync.Mutex
	file   *parsedFile
	count  int // tabs subscribed; nothing is built while zero
	poke   chan struct{}
}

func newRuleState() *ruleState {
	rs := &ruleState{queues: queue.NewRegistry(), poke: make(chan struct{}, 1)}
	if err := queue.CreateBroadcastingWithFullAction[[]byte](rs.queues, stateQueue, stateQueueCapacity, queue.FullDropOldest); err != nil {
		panic(err) // a fresh registry cannot already hold the queue
	}
	rs.frames, _ = queue.AcquireSender[[]byte](rs.queues, stateQueue)
	return rs
}

// configFile returns the parsed config file, reading it only if it changed.
func (c *Console) configFile() *parsedFile {
	rs := c.rules
	path := c.srv.configPath
	st, err := os.Stat(path)
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if err == nil && rs.file != nil && st.ModTime().Equal(rs.file.mtime) && st.Size() == rs.file.size {
		return rs.file
	}
	pf := &parsedFile{view: fileView{Path: path}}
	if path == "" {
		pf.view.Error = "this proxy was not started from a config file"
		rs.file = pf
		return pf
	}
	configFileMu.Lock()
	data, err := os.ReadFile(path)
	var ver fileVersion
	if err == nil {
		ver, err = versionOf(path, data)
	}
	configFileMu.Unlock()
	if err != nil {
		pf.view.Error = err.Error()
		return pf // not cached: try again next time
	}
	pf.view.Hash, pf.view.Mtime = ver.Hash, ver.Mtime
	if st != nil {
		pf.mtime, pf.size = st.ModTime(), st.Size()
	}
	if pf.cfg, err = ParseConfig(string(data)); err != nil {
		pf.view.Error = "the config file does not load (" + err.Error() + "); the console shows the running configuration and cannot edit it until the file is fixed"
	} else {
		pf.view.Editable = true
		pf.text, pf.lines, pf.blocks = string(data), strings.Split(string(data), "\n"), map[int]block{}
		for _, header := range []string{hostHeader, listenerHeader} {
			for _, b := range sectionBlocks(pf.lines, header) {
				pf.blocks[b.start+1] = b
			}
		}
	}
	rs.file = pf
	return pf
}

func connDirState(v int32) string {
	if v == dirOpen {
		return "open"
	}
	return "half-closed"
}

func secondsOrNil(d *time.Duration) *int {
	if d == nil {
		return nil
	}
	s := int(d.Seconds())
	return &s
}

// state builds one frame (Now left for the caller).
func (c *Console) state() consoleState {
	st, rt := c.srv.stats, c.srv.runtime.Load()
	pf := c.configFile()
	stopped := c.srv.stoppedRules()
	running := map[string]bool{}
	for i := range rt.cfg.Rules {
		running[rt.cfg.Rules[i].Key()] = true
	}
	shown := rt.cfg
	if pf.cfg != nil {
		shown = pf.cfg
	}
	values := func(line int) map[string]string {
		if pf.cfg == nil {
			return map[string]string{}
		}
		if b, ok := pf.blocks[line]; ok {
			return blockValues(pf.lines, b)
		}
		return map[string]string{}
	}

	byRule := map[string][]*ConnState{}
	ruleListener, rulePattern := map[string]string{}, map[string]string{}
	st.conns.Range(func(cs *ConnState) bool {
		cs.mu.Lock()
		key := cs.RuleKey
		if key != "" {
			ruleListener[key], rulePattern[key] = cs.Listener, cs.rulePattern
		}
		cs.mu.Unlock()
		if key != "" {
			byRule[key] = append(byRule[key], cs)
		}
		return true
	})

	listed := map[string]bool{}
	view := func(v ruleView) ruleView {
		key := v.Key
		listed[key] = true
		if rs := st.ruleSnapshot(key); rs != nil {
			v.Active, v.Total, v.BytesUp, v.BytesDown = rs.Active.Load(), rs.Total.Load(), rs.BytesUp.Load(), rs.BytesDown.Load()
		}
		conns := byRule[key]
		sort.Slice(conns, func(i, j int) bool { return conns[i].ID < conns[j].ID })
		v.ConnCount = len(conns)
		v.Connections = []connView{}
		for _, cs := range conns[:min(len(conns), maxFrameConns)] {
			cs.mu.Lock()
			cv := connView{ID: cs.ID, Started: cs.Start.UnixMilli(), Src: cs.Src, Local: cs.Local, UpstreamLocal: cs.UpLocal,
				Peer: cs.Peer, SNI: cs.SNI, Dst: cs.Dst, Mode: cs.Mode, Terminated: cs.Mode != "",
				Stopping: cs.killReason != "" || cs.closed}
			cs.mu.Unlock()
			cv.BytesUp, cv.BytesDown = cs.BytesUp.Load(), cs.BytesDown.Load()
			cv.CToS, cv.SToC = connDirState(cs.CToS.Load()), connDirState(cs.SToC.Load())
			cv.LastActivity = cs.lastActivityUnixNano.Load() / 1e6
			v.Connections = append(v.Connections, cv)
		}
		return v
	}

	var listeners []listenerView
	index := map[string]int{}
	addListener := func(lv listenerView) {
		lv.Addrs, lv.Running, lv.Stopped, lv.Error = c.srv.listenerState(lv.Name)
		if lv.Addrs == nil {
			lv.Addrs = []string{}
		}
		if ls := st.listenerSnapshot(lv.Name); ls != nil {
			lv.Active, lv.Accepted, lv.Rejected = ls.Active.Load(), ls.Accepted.Load(), ls.Rejected.Load()
			lv.BytesUp, lv.BytesDown = ls.BytesUp.Load(), ls.BytesDown.Load()
		}
		lv.Rules = []ruleView{}
		index[lv.Name] = len(listeners)
		listeners = append(listeners, lv)
	}
	for i := range shown.Listeners {
		l := &shown.Listeners[i]
		lv := listenerView{Name: l.Name, Line: l.Line, Implicit: l.Line == 0, Bind: l.Bind, Port: l.Port,
			Values: values(l.Line), MaxConnections: l.MaxConnections,
			HandshakeTimeout: secondsOrNil(l.HandshakeTimeout), IdleTimeout: secondsOrNil(l.IdleTimeout), HalfCloseTimeout: secondsOrNil(l.HalfCloseTimeout),
			AggSpeed: l.MaxAggregatedSpeed, ConnSpeed: l.MaxSingleConnectionSpeed}
		if l.Line == 0 {
			lv.Values = map[string]string{}
		}
		if l.ProxyProtocolFrom != nil {
			var p []string
			for _, x := range *l.ProxyProtocolFrom {
				p = append(p, x.String())
			}
			lv.ProxyProtocolFrom = strings.Join(p, ", ")
		}
		addListener(lv)
	}
	if l := shown.Redirect; l != nil {
		addListener(listenerView{Name: l.Name, Redirect: true, Bind: l.Bind, Port: l.Port, Values: map[string]string{}})
	}
	for i := range shown.Rules {
		r := &shown.Rules[i]
		v := ruleView{Listener: r.Listener, Line: r.Line, Key: r.Key(), Pattern: r.Source, Kind: r.Kind.String(), Allow: r.Allow,
			Terminates: r.Terminates(), Cert: r.Cert, Proxy: r.Proxy, ProxyVersion: r.ProxyVersion,
			AggSpeed: r.MaxAggregatedSpeed, ConnSpeed: r.MaxSingleConnectionSpeed,
			Stopped: stopped[r.Key()], Running: running[r.Key()], Values: values(r.Line)}
		if r.Allow {
			v.Target = net.JoinHostPort(r.TargetHost, strconv.Itoa(r.TargetPort))
		}
		if pf.cfg == nil {
			v.Line = 0 // line numbers of a config that is not the file's
		}
		lv := &listeners[index[r.Listener]]
		lv.Rules = append(lv.Rules, view(v))
	}
	// The redirect listener's connections, shown as one pseudo-rule.
	if shown.Redirect != nil {
		lv := &listeners[index[shown.Redirect.Name]]
		lv.Rules = append(lv.Rules, view(ruleView{Listener: shown.Redirect.Name, Key: redirectKey, Pattern: redirectPattern, Kind: "redirect",
			Allow: true, Target: "https://", Running: rt.cfg.Redirect != nil, Values: map[string]string{}}))
	}
	// Connections of a rule (or listener) that is gone still show up.
	var orphans []string
	for key := range byRule {
		if !listed[key] {
			orphans = append(orphans, key)
		}
	}
	sort.Strings(orphans)
	for _, key := range orphans {
		name := ruleListener[key]
		if _, ok := index[name]; !ok {
			addListener(listenerView{Name: name, Removed: true, Values: map[string]string{}})
		}
		pattern := rulePattern[key]
		if pattern == "" {
			pattern = key
		}
		lv := &listeners[index[name]]
		lv.Rules = append(lv.Rules, view(ruleView{Listener: name, Key: key, Pattern: pattern, Kind: "removed", Values: map[string]string{}}))
	}
	host, _ := os.Hostname()
	return consoleState{
		Host: host, Started: st.Started.UnixMilli(), File: pf.view, Listeners: listeners,
		Status: statusView{Active: st.Active.Load(), Accepted: st.Accepted.Load(),
			Completed: st.Completed.Load(), Denied: st.Denied.Load(), Failed: st.Failed.Load(), Rejected: st.Rejected.Load(),
			MaxConnections: rt.cfg.MaxConnections, BytesUp: st.BytesUp.Load(), BytesDown: st.BytesDown.Load()},
	}
}

// poke asks for a frame now: an action from the console shows without
// waiting for the next tick.
func (c *Console) poke() {
	select {
	case c.rules.poke <- struct{}{}:
	default:
	}
}

// frame marshals the state, or returns nil when nothing changed since prev
// (the time stamp aside).
func (c *Console) frame(prev []byte) (frame, cmp []byte) {
	s := c.state()
	cmp, err := json.Marshal(s)
	if err != nil || string(cmp) == string(prev) {
		return nil, prev
	}
	s.Now = time.Now().UnixMilli()
	frame, _ = json.Marshal(s)
	return frame, cmp
}

// broadcast is the stats emitter: every pushInterval it checks whether
// anything changed and, if so, publishes one frame to the state queue. No
// change, no event. Nothing is built while no tab is subscribed.
func (c *Console) broadcast() {
	tick := time.NewTicker(pushInterval)
	defer tick.Stop()
	var last []byte
	for {
		select {
		case <-tick.C:
		case <-c.rules.poke:
		}
		c.rules.mu.Lock()
		viewers := c.rules.count
		c.rules.mu.Unlock()
		if viewers == 0 {
			last = nil // a tab that subscribes later gets a full frame anyway
			continue
		}
		var f []byte
		if f, last = c.frame(last); f != nil {
			c.rules.frames.Send(f) // never blocks: drop-oldest
		}
	}
}

func (c *Console) stateGet(w http.ResponseWriter, r *http.Request) {
	s := c.state()
	s.Now = time.Now().UnixMilli()
	writeJSON(w, 200, s)
}

// stateSocket pushes frames to one tab until it leaves, signs out or its
// session expires.
func (c *Console) stateSocket(w http.ResponseWriter, r *http.Request) {
	ws, err := upgradeWebSocket(w, r)
	if err != nil {
		return
	}
	defer ws.Close()
	rx, err := queue.AcquireReceiver[[]byte](c.rules.queues, stateQueue)
	if err != nil {
		return
	}
	defer rx.Close()
	c.rules.mu.Lock()
	c.rules.count++
	c.rules.mu.Unlock()
	defer func() {
		c.rules.mu.Lock()
		c.rules.count--
		c.rules.mu.Unlock()
	}()
	done := make(chan struct{})
	defer close(done)
	gone := make(chan struct{})
	go func() {
		_ = ws.readLoop()
		close(gone)
	}()
	// Recv cannot be cancelled, so a watcher closes the receiver when the tab
	// leaves, its session ends (sign-out, expiry) or a ping fails.
	go func() {
		ping := time.NewTicker(wsPingInterval)
		check := time.NewTicker(time.Second)
		defer ping.Stop()
		defer check.Stop()
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
			}
			rx.Close()
			ws.Close()
			return
		}
	}()
	// A new subscriber starts at the queue's tail, so send the current state
	// first; frames published from now on follow.
	s := c.state()
	s.Now = time.Now().UnixMilli()
	data, err := json.Marshal(s)
	if err != nil || ws.writeFrame(wsOpText, data) != nil {
		return
	}
	for {
		frame, err := rx.Recv()
		if err != nil {
			return
		}
		if ws.writeFrame(wsOpText, frame) != nil {
			return
		}
	}
}

// ---------------------------------------------------------------- actions

func (c *Console) ruleStopStart(stop bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Key string }
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.Key == "" {
			fail(w, 400, "bad request")
			return
		}
		var rule *Rule
		cfg := c.srv.runtime.Load().cfg
		for i := range cfg.Rules {
			if cfg.Rules[i].Key() == req.Key {
				rule = &cfg.Rules[i]
			}
		}
		if rule == nil && stop {
			fail(w, 404, "no such rule in the running configuration")
			return
		}
		c.srv.setRuleStopped(req.Key, stop)
		name := req.Key
		if rule != nil {
			name = fmt.Sprintf("%s (line %d)", rule.Source, rule.Line)
		}
		if stop {
			logf("console: rule %s stopped from %s: names it matched now go to the next rule; its connections were closed", name, r.RemoteAddr)
		} else {
			logf("console: rule %s started from %s", name, r.RemoteAddr)
		}
		c.poke()
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

func (c *Console) connStop(w http.ResponseWriter, r *http.Request) {
	var req struct{ ID uint64 }
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		fail(w, 400, "bad request")
		return
	}
	st := c.srv.stats
	cs, _ := st.conns.Load(req.ID)
	if cs == nil {
		fail(w, 404, "no such connection (it may have just closed)")
		return
	}
	sni, dst, _ := cs.info()
	logf("console: connection #%d (%s, sni=%s -> %s) stopped from %s", req.ID, cs.Src, sni, dst, r.RemoteAddr)
	cs.stop("stopped from the console; closed by proxy")
	c.poke()
	writeJSON(w, 200, map[string]any{"ok": true})
}

type ruleEditRequest struct {
	Line      int
	BaseHash  string
	BaseMtime string
	Values    map[string]string
	SNIs      []string // validate only: names to route through the edited config
}

func (c *Console) ruleSave(w http.ResponseWriter, r *http.Request)   { c.ruleEdit(w, r, false) }
func (c *Console) ruleDelete(w http.ResponseWriter, r *http.Request) { c.ruleEdit(w, r, true) }

// ruleValidate is the editor's dry run, called as the user types: it applies
// the values to the file as it is now and reports whether the result loads,
// the [[host]] block that would be written, warnings, and where sample names
// would be routed. Nothing is written.
func (c *Console) ruleValidate(w http.ResponseWriter, r *http.Request) {
	var req ruleEditRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		fail(w, 400, "bad request")
		return
	}
	configFileMu.Lock()
	onDisk, _, _, ver, err := c.readConfig()
	configFileMu.Unlock()
	if err != nil {
		fail(w, 500, "%v", err)
		return
	}
	resp := map[string]any{"ok": false, "stale": req.Line > 0 && (req.BaseMtime != ver.Mtime || req.BaseHash != ver.Hash)}
	full, err := editRules(string(onDisk), req.Line, req.Values, false)
	if err != nil {
		resp["error"] = err.Error()
		writeJSON(w, 200, resp)
		return
	}
	// The block as it would be written: find it in the edited text.
	lines := strings.Split(full, "\n")
	blocks := hostBlocks(lines)
	b := blocks[len(blocks)-1] // a new rule goes after the last one
	if req.Line > 0 {
		for _, x := range blocks {
			if x.start == req.Line-1 {
				b = x
			}
		}
	}
	resp["block"] = strings.Join(lines[b.start:b.end], "\n")
	cfg, err := ParseConfig(full)
	if err == nil {
		err = c.srv.certs.Check(cfg)
	}
	if err != nil {
		resp["error"] = err.Error()
		writeJSON(w, 200, resp)
		return
	}
	// Route with the rules of the edited rule's listener.
	eff := cfg
	for i := range cfg.Rules {
		if cfg.Rules[i].Line == b.start+1 {
			eff = cfg.ForListener(cfg.Listener(cfg.Rules[i].Listener))
		}
	}
	var routes []map[string]any
	for _, sni := range req.SNIs {
		name := strings.ToLower(strings.TrimSpace(sni))
		d := eff.RouteExcept(name, c.srv.stoppedRules())
		row := map[string]any{"sni": sni, "allow": d.Allow, "error": d.Err, "thisRule": d.RuleLine == b.start+1}
		if d.Rule != nil {
			row["pattern"], row["kind"], row["ruleLine"] = d.Rule.Source, d.Rule.Kind.String(), d.RuleLine
		}
		if d.Allow {
			row["target"] = net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
		}
		routes = append(routes, row)
	}
	resp["ok"], resp["warnings"], resp["routes"] = true, cfg.Warnings, routes
	writeJSON(w, 200, resp)
}

// ruleEdit changes one rule in the file and applies it, through the same
// checks as the config editor: the file must be the version the console
// showed, the result must load, the old file is kept as a backup.
func (c *Console) ruleEdit(w http.ResponseWriter, r *http.Request, del bool) {
	var req ruleEditRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil || (del && req.Line <= 0) {
		fail(w, 400, "bad request")
		return
	}
	configFileMu.Lock()
	defer configFileMu.Unlock()
	onDisk, _, _, ver, err := c.readConfig()
	if err != nil {
		fail(w, 500, "%v", err)
		return
	}
	if req.BaseMtime != ver.Mtime || req.BaseHash != ver.Hash {
		fail(w, http.StatusConflict, "not saved: the config file changed after this page loaded it. The rules shown are now up to date; try again")
		return
	}
	full, err := editRules(string(onDisk), req.Line, req.Values, del)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	cfg, err := ParseConfig(full)
	if err == nil {
		err = c.srv.certs.Check(cfg)
	}
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	what := "added"
	switch {
	case del:
		what = fmt.Sprintf("at line %d deleted", req.Line)
	case req.Line > 0:
		what = fmt.Sprintf("at line %d changed", req.Line)
	}
	c.commit(w, r, onDisk, full, cfg, "rule "+what)
}

// ---------------------------------------------------------------- listeners

type listenerEditRequest struct {
	Line      int
	Implicit  bool // edit the listener made from [global]
	BaseHash  string
	BaseMtime string
	Values    map[string]string
}

// listenerChange applies a listener edit to the file as it is now. The
// caller holds configFileMu if it goes on to write.
func (c *Console) listenerChange(req listenerEditRequest, del bool) (onDisk []byte, full string, at int, notes []string, cfg *Config, ver fileVersion, err error) {
	if onDisk, _, _, ver, err = c.readConfig(); err != nil {
		return
	}
	if del {
		// Say which rules hold it, rather than the parser's complaint about them.
		if cur, perr := ParseConfig(string(onDisk)); perr == nil {
			for _, l := range cur.Listeners {
				if l.Line != req.Line {
					continue
				}
				var held []string
				for _, r := range cur.Rules {
					if r.Listener == l.Name {
						held = append(held, fmt.Sprintf("%s (line %d)", r.Source, r.Line))
					}
				}
				if len(held) > 0 {
					err = fmt.Errorf("listener %s still has %d rule(s): %s. Delete them or move them to another listener first", l.Name, len(held), strings.Join(held, ", "))
					return
				}
			}
		}
	}
	if full, at, notes, err = editListeners(string(onDisk), req.Line, req.Implicit, req.Values, del); err != nil {
		return
	}
	if cfg, err = ParseConfig(full); err == nil {
		err = c.srv.certs.Check(cfg)
	}
	return
}

// listenerValidate is the listener editor's dry run: the block that would be
// written, the notes on what else changes, errors and warnings.
func (c *Console) listenerValidate(w http.ResponseWriter, r *http.Request) {
	var req listenerEditRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		fail(w, 400, "bad request")
		return
	}
	configFileMu.Lock()
	_, full, at, notes, cfg, ver, err := c.listenerChange(req, false)
	configFileMu.Unlock()
	resp := map[string]any{"ok": err == nil, "stale": req.Line > 0 && (req.BaseMtime != ver.Mtime || req.BaseHash != ver.Hash), "notes": notes}
	if full != "" {
		lines := strings.Split(full, "\n")
		if b := blockAt(sectionBlocks(lines, listenerHeader), at); b != nil {
			resp["block"] = strings.Join(lines[b.start:b.end], "\n")
		}
	}
	if err != nil {
		resp["error"] = err.Error()
	} else {
		resp["warnings"] = cfg.Warnings
	}
	writeJSON(w, 200, resp)
}

func (c *Console) listenerSave(w http.ResponseWriter, r *http.Request)   { c.listenerEdit(w, r, false) }
func (c *Console) listenerDelete(w http.ResponseWriter, r *http.Request) { c.listenerEdit(w, r, true) }

func (c *Console) listenerEdit(w http.ResponseWriter, r *http.Request, del bool) {
	var req listenerEditRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil || (del && req.Line <= 0) {
		fail(w, 400, "bad request")
		return
	}
	configFileMu.Lock()
	defer configFileMu.Unlock()
	onDisk, full, _, notes, cfg, ver, err := c.listenerChange(req, del)
	if err == nil && (req.BaseMtime != ver.Mtime || req.BaseHash != ver.Hash) {
		fail(w, http.StatusConflict, "not saved: the config file changed after this page loaded it. The console now shows the current version; try again")
		return
	}
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	what := "listener added"
	switch {
	case del:
		what = fmt.Sprintf("listener at line %d deleted", req.Line)
	case req.Implicit:
		what = "the [global] listener turned into a [[listener]]"
	case req.Line > 0:
		what = fmt.Sprintf("listener at line %d changed", req.Line)
	}
	if len(notes) > 0 {
		what += " (" + strings.Join(notes, "; ") + ")"
	}
	c.commit(w, r, onDisk, full, cfg, what)
}

func (c *Console) listenerStopStart(stop bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Name string }
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.Name == "" {
			fail(w, 400, "bad request")
			return
		}
		err := c.srv.setListenerStopped(req.Name, stop)
		c.poke()
		if err != nil {
			fail(w, 409, "%v", err)
			return
		}
		if stop {
			logf("console: listener %s stopped from %s: its port is closed and its connections were closed", req.Name, r.RemoteAddr)
		} else {
			logf("console: listener %s started from %s", req.Name, r.RemoteAddr)
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

// consoleMoved reports a [console] listen or port change: listeners follow a
// reload, the console itself needs a restart.
func consoleMoved(next, running *ConsoleConfig) bool {
	if next == nil || running == nil {
		return next != running
	}
	return next.Listen != running.Listen || next.Port != running.Port
}

// commit writes full over onDisk (kept as a timestamped backup), reloads at
// once and answers with the new version. The caller holds configFileMu.
func (c *Console) commit(w http.ResponseWriter, r *http.Request, onDisk []byte, full string, cfg *Config, what string) {
	if full == string(onDisk) {
		ver, _ := versionOf(c.srv.configPath, onDisk)
		writeJSON(w, 200, map[string]any{"ok": true, "unchanged": true, "hash": ver.Hash, "mtime": ver.Mtime})
		return
	}
	path := c.srv.configPath
	backup := fmt.Sprintf("%s.%s.bak", path, time.Now().UTC().Format("20060102T150405.000Z"))
	if err := writeFileAtomic(backup, onDisk); err != nil {
		fail(w, 500, "cannot write the backup: %v", err)
		return
	}
	if err := writeFileAtomic(path, []byte(full)); err != nil {
		fail(w, 500, "cannot write %s: %v", path, err)
		return
	}
	pruneBackups(path)
	now, err := versionOf(path, []byte(full))
	if err != nil {
		fail(w, 500, "saved, but cannot stat %s: %v", path, err)
		return
	}
	logf("console: %s from %s (previous version kept as %s)", what, r.RemoteAddr, filepath.Base(backup))
	// Apply it now instead of at the next poll, and wait to hear how that
	// went: a port that cannot be opened is reported with the save.
	var problems []string
	reply := make(chan []string, 1)
	wait := time.NewTimer(reloadWait)
	defer wait.Stop()
	select {
	case c.srv.reloadNow <- reply:
		select {
		case problems = <-reply:
		case <-wait.C:
			problems = []string{"saved, but applying it is taking long; watch the listener cards"}
		}
	case <-wait.C:
		problems = []string{"saved, but applying it is taking long; watch the listener cards"}
	}
	c.poke()
	running := c.srv.runtime.Load().cfg
	writeJSON(w, 200, map[string]any{"ok": true, "hash": now.Hash, "mtime": now.Mtime, "backup": filepath.Base(backup),
		"warnings": cfg.Warnings, "problems": problems, "restartNeeded": consoleMoved(cfg.Console, running.Console)})
}
