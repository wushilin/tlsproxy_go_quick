package pfrelay

import (
	"context"
	"errors"
	"time"

	"github.com/wushilin/pf-simple/internal/relayhook"
	"github.com/wushilin/pf-simple/internal/tunnel"
)

// A Client can be driven by another transport than WebSocket: pfrelayquic
// attaches its QUIC transport through relayhook. Everything but reaching
// the hub (listeners, retries, reasons, events, stats) stays here, so the
// two behave alike.

func init() {
	relayhook.Attach = func(client any, t relayhook.Transport) { client.(*Client).alt = t }
}

var errNoOpen = errors.New("the server's request for this connection is gone")

// params are what the attached transport needs of c.
func (c *Client) params() relayhook.Params {
	agent := c.Agent
	if agent == "" {
		agent = DefaultAgent
	}
	return relayhook.Params{
		Base: c.base, Word: c.word, ServeToken: c.ServeToken, Name: c.Name, ClientToken: c.ClientToken,
		Agent: agent, TLS: c.tls, Logf: c.Logf,
	}
}

// connectStream opens one connection through the tunnel: its stream and id.
func (c *Client) connectStream(ctx context.Context) (*tunnel.Stream, string, error) {
	if c.alt != nil {
		return c.alt.Connect(ctx, c.params())
	}
	ws, err := c.dial(ctx, "connect", c.connectHeader())
	if err != nil {
		return nil, "", err
	}
	return tunnel.NewStream(ws), ws.Header.Get(tunnel.HeaderConn), nil
}

// refuseOpen tells the hub why this side cannot carry connection id.
func (c *Client) refuseOpen(ctx context.Context, reg *registration, id, reason string) error {
	if reg != nil && reg.alt != nil {
		if o := reg.takeAlt(id); o != nil {
			o.Refuse(reason)
		}
		return nil
	}
	h := c.header(id)
	h.Set(tunnel.HeaderError, reason)
	return c.get(ctx, "accept", h)
}

func (r *registration) putAlt(o relayhook.Open) {
	r.mu.Lock()
	if r.altOpens == nil {
		r.altOpens = map[string]relayhook.Open{}
	}
	r.altOpens[o.ID()] = o
	r.mu.Unlock()
}

func (r *registration) takeAlt(id string) relayhook.Open {
	r.mu.Lock()
	defer r.mu.Unlock()
	o := r.altOpens[id]
	delete(r.altOpens, id)
	return o
}

// serveAlt is serve over the attached transport: it keeps a registration
// and calls open for each connection the hub asks for, retrying as serve
// does.
func (c *Client) serveAlt(ctx context.Context, target string, open func(reg *registration, id string, leg *tunnel.Stream), up func(bool)) error {
	rt := timing()
	backoff, served := rt.min, false
	for attempt := 1; ; attempt++ {
		alt, err := c.alt.Register(ctx, c.params(), target)
		if ctx.Err() != nil {
			if alt != nil {
				alt.Close()
			}
			return nil
		}
		if err != nil {
			var se *tunnel.StatusError
			if errors.As(err, new(*tunnel.ProtoError)) {
				return err
			}
			if !served && errors.As(err, &se) && se.Final() {
				return explain(err)
			}
			c.logf("cannot register with %s (%v); attempt %d, trying again in %s", c.base, explain(err), attempt, backoff)
		} else {
			if served {
				c.logf("registered again with %s over QUIC after %d attempt(s): serving %q, tunnel %s -> %s", c.base, attempt, c.Name, c.wordLabel(), target)
			} else {
				c.logf("registered with %s over QUIC: serving %q, tunnel %s -> %s", c.base, c.Name, c.wordLabel(), target)
			}
			served, attempt = true, 0
			started := time.Now()
			if up != nil {
				up(true)
			}
			c.serving(true)
			reg := &registration{c: c, open: open, alt: alt}
			reg.ctx, reg.cancel = context.WithCancel(ctx)
			for {
				o, nerr := alt.Next(reg.ctx)
				if nerr != nil {
					err = nerr
					break
				}
				reg.putAlt(o)
				go open(reg, o.ID(), nil)
			}
			reg.cancel()
			alt.Close()
			if up != nil {
				up(false)
			}
			c.serving(false)
			if ctx.Err() != nil {
				return nil
			}
			if time.Since(started) >= rt.settled {
				backoff = rt.min
			}
			c.logf("lost the server after %s (%v); its connections are closed; registering again in %s", fmtAge(time.Since(started)), err, backoff)
		}
		if !sleep(ctx, backoff) {
			return nil
		}
		backoff = min(backoff*2, rt.max)
	}
}
