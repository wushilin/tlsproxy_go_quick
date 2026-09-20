package main

// Connecting to a target. A host-name target is resolved through a small
// cache, so a busy name costs the resolver one lookup every few seconds rather
// than one per connection; the addresses are then dialled the way net.Dialer
// would have (Happy Eyeballs, RFC 8305): the preferred family first, the other
// one 300 ms later if nothing has connected, first success wins.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"
)

const (
	dnsCacheTTL      = 5 * time.Second // short: a changed record is picked up almost at once
	dnsCacheSize     = 1024            // names can come from clients ($1 in target_host)
	happyEyeballsLag = 300 * time.Millisecond
)

type dnsEntry struct {
	addrs   []netip.Addr
	expires time.Time
}

// targetDialer resolves (with the cache) and connects.
type targetDialer struct {
	cache *lru[dnsEntry]
	// Overridable in tests.
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	dial   func(ctx context.Context, addr string) (net.Conn, error)
}

func newTargetDialer() *targetDialer {
	return &targetDialer{
		cache: newLRU[dnsEntry](dnsCacheSize),
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		dial: func(ctx context.Context, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		},
	}
}

// resolve returns host's addresses in the resolver's order (RFC 6724). Only
// successful lookups are cached: a failure is retried by the next connection.
func (d *targetDialer) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	if e, ok := d.cache.Get(host); ok && time.Now().Before(e.expires) {
		return e.addrs, nil
	}
	addrs, err := d.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}
	d.cache.Put(host, dnsEntry{addrs: addrs, expires: time.Now().Add(dnsCacheTTL)})
	return addrs, nil
}

// Dial connects to host:port within timeout.
func (d *targetDialer) Dial(host string, port int, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	addrs, err := d.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	// The family of the first address is preferred; the other is the fallback.
	var primary, fallback []string
	for _, a := range addrs {
		target := net.JoinHostPort(a.String(), strconv.Itoa(port))
		if a.Unmap().Is4() == addrs[0].Unmap().Is4() {
			primary = append(primary, target)
		} else {
			fallback = append(fallback, target)
		}
	}
	if len(fallback) == 0 {
		return d.dialSerial(ctx, primary)
	}

	type result struct {
		conn    net.Conn
		err     error
		primary bool
	}
	results := make(chan result) // unbuffered: a connection is never left in a channel
	raceCtx, stop := context.WithCancel(ctx)
	defer stop()
	run := func(targets []string, isPrimary bool) {
		conn, err := d.dialSerial(raceCtx, targets)
		select {
		case results <- result{conn, err, isPrimary}:
		case <-raceCtx.Done(): // the other family won
			if conn != nil {
				conn.Close()
			}
		}
	}
	go run(primary, true)
	lag := time.NewTimer(happyEyeballsLag)
	defer lag.Stop()
	fallbackStarted, failures := false, 0
	var firstErr error
	for {
		select {
		case <-ctx.Done():
			// Out of time. Attempts still running see the same context and give
			// up by themselves; their results are not waited for (they may choose
			// not to report once the context is done).
			if firstErr == nil {
				firstErr = fmt.Errorf("dial %s: %w", net.JoinHostPort(host, strconv.Itoa(port)), os.ErrDeadlineExceeded)
			}
			return nil, firstErr
		case <-lag.C:
			if !fallbackStarted {
				fallbackStarted = true
				go run(fallback, false)
			}
		case r := <-results:
			if r.err == nil {
				return r.conn, nil
			}
			if r.primary || firstErr == nil {
				firstErr = r.err // report the preferred family's error
			}
			if failures++; failures == 2 {
				return nil, firstErr
			}
			if !fallbackStarted { // the preferred family failed fast: don't wait out the lag
				fallbackStarted = true
				go run(fallback, false)
			}
		}
	}
}

// dialSerial tries the addresses one after the other, giving each a fair share
// of the time that is left.
func (d *targetDialer) dialSerial(ctx context.Context, targets []string) (net.Conn, error) {
	var firstErr error
	for i, target := range targets {
		attempt, cancel := ctx, context.CancelFunc(func() {})
		if deadline, ok := ctx.Deadline(); ok {
			share := time.Until(deadline) / time.Duration(len(targets)-i)
			if share < 2*time.Second && i < len(targets)-1 {
				share = min(2*time.Second, time.Until(deadline)) // too little to be a real attempt otherwise
			}
			attempt, cancel = context.WithTimeout(ctx, share)
		}
		conn, err := d.dial(attempt, target)
		cancel()
		if err == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	if firstErr == nil {
		firstErr = errors.New("no addresses to connect to")
	}
	return nil, firstErr
}
