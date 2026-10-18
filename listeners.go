package main

// Live listeners: the ports the proxy accepts on, opened and closed to match
// the configuration as it is reloaded, and stopped or started from the
// console (in memory only: a restart opens every configured listener).

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
)

// liveListener is one configured listener's state in this process.
type liveListener struct {
	name    string
	addrs   []string       // what it is bound to, as configured ("0.0.0.0:443")
	lns     []net.Listener // open sockets; nil when closed
	err     string         // why the last attempt to open failed
	adopted bool           // sockets handed to Serve by the caller (tests): never reopened
}

func (l *liveListener) open() bool { return len(l.lns) > 0 }

func (l *liveListener) close() {
	for _, ln := range l.lns {
		ln.Close() // its accept loop ends
	}
	l.lns = nil
}

// bindListener opens every address of l, or none.
func bindListener(l *Listener) ([]net.Listener, error) {
	var lns []net.Listener
	for _, bind := range l.Binds {
		network := listenNetwork(bind)
		if len(l.Binds) > 1 && network == "tcp" {
			network = "tcp6" // several addresses: each listens for its own family only
		}
		ln, err := net.Listen(network, net.JoinHostPort(bind, strconv.Itoa(l.Port)))
		if err != nil {
			for _, open := range lns {
				open.Close()
			}
			return nil, err
		}
		lns = append(lns, ln)
	}
	return lns, nil
}

// syncListeners makes the open ports match cfg: new listeners are opened,
// removed ones closed, moved ones (bind or port changed) reopened, stopped
// ones kept closed. Connections already accepted are not affected. A port
// that cannot be opened is logged, shown in the console and returned; the
// other listeners carry on.
func (s *Server) syncListeners(cfg *Config) (failed []string) {
	s.listenersMu.Lock()
	defer s.listenersMu.Unlock()
	if s.listeners == nil {
		s.listeners = map[string]*liveListener{}
	}
	want := map[string]bool{}
	for i := range cfg.Listeners {
		l := &cfg.Listeners[i]
		want[l.Name] = true
		live := s.listeners[l.Name]
		addrs := l.Addrs()
		if live != nil && live.adopted {
			continue
		}
		if live != nil && slices.Equal(live.addrs, addrs) && (live.open() || s.stoppedListeners[l.Name]) {
			continue // unchanged
		}
		if live != nil {
			live.close()
			if !slices.Equal(live.addrs, addrs) {
				logf("listener %s: moving from %s to %s", l.Name, strings.Join(live.addrs, ", "), strings.Join(addrs, ", "))
			}
		}
		live = &liveListener{name: l.Name, addrs: addrs}
		s.listeners[l.Name] = live
		if s.stoppedListeners[l.Name] {
			continue
		}
		if err := s.openLocked(live, l); err != nil {
			msg := fmt.Sprintf("listener %s: cannot listen on %s: %v", l.Name, strings.Join(addrs, ", "), err)
			errorf("%s", msg)
			failed = append(failed, msg)
		}
	}
	for name, live := range s.listeners {
		if !want[name] {
			live.close()
			delete(s.listeners, name)
			delete(s.stoppedListeners, name)
			logf("listener %s: removed from the configuration; %s closed (its open connections continue)", name, strings.Join(live.addrs, ", "))
		}
	}
	return failed
}

// openLocked binds live's addresses and starts accepting.
func (s *Server) openLocked(live *liveListener, l *Listener) error {
	lns, err := bindListener(l)
	if err != nil {
		live.err = err.Error()
		return err
	}
	live.lns, live.err = lns, ""
	for _, ln := range lns {
		s.stats.GoroutinesStarted.Add(1)
		go func() {
			defer s.stats.GoroutinesFinished.Add(1)
			s.acceptLoop(ln, l.Name)
		}()
	}
	if s.serving {
		logf("listener %s: listening on %s", l.Name, strings.Join(live.addrs, ", "))
	}
	return nil
}

// setListenerStopped stops (closes the port and its connections) or starts a
// listener.
func (s *Server) setListenerStopped(name string, stop bool) error {
	cfg := s.runtime.Load().cfg
	l := cfg.Listener(name)
	if l == nil {
		return fmt.Errorf("no listener named %s in the running configuration", name)
	}
	s.listenersMu.Lock()
	live := s.listeners[name]
	if live == nil {
		s.listenersMu.Unlock()
		return fmt.Errorf("listener %s is not set up yet", name)
	}
	if live.adopted {
		s.listenersMu.Unlock()
		return errors.New("this listener was handed to the proxy by its caller and cannot be stopped")
	}
	if s.stoppedListeners == nil {
		s.stoppedListeners = map[string]bool{}
	}
	var err error
	if stop {
		s.stoppedListeners[name] = true
		live.close()
		live.err = ""
	} else if !live.open() {
		// A port that cannot be opened leaves the listener as it was: still
		// stopped if it was, with the error showing.
		if err = s.openLocked(live, l); err == nil {
			delete(s.stoppedListeners, name)
		}
	} else {
		delete(s.stoppedListeners, name)
	}
	s.listenersMu.Unlock()
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %v", strings.Join(live.addrs, ", "), err)
	}
	if stop {
		var victims []*ConnState
		s.stats.conns.Range(func(c *ConnState) bool {
			if c.Listener == name {
				victims = append(victims, c)
			}
			return true
		})
		for _, c := range victims {
			c.stop("listener stopped from the console; closed by proxy")
		}
	}
	return nil
}

// listenerState is what the console shows about one listener's port.
func (s *Server) listenerState(name string) (addrs []string, open, stopped bool, err string) {
	s.listenersMu.Lock()
	defer s.listenersMu.Unlock()
	live := s.listeners[name]
	if live == nil {
		return nil, false, s.stoppedListeners[name], ""
	}
	for _, ln := range live.lns {
		addrs = append(addrs, ln.Addr().String())
	}
	return addrs, live.open(), s.stoppedListeners[name], live.err
}
