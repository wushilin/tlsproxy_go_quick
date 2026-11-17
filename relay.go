package main

// Relay targets. A rule whose target is relay://<endpoint> reaches its
// backend through a tunnel of a pf-simple relay hub
// (github.com/wushilin/pf-simple) over QUIC, tunnel protocol 3, instead of
// dialling a host:port. Two sections describe it:
//
//	exchanges:   a hub: its https address, and the CA it is trusted with
//	endpoints:   a tunnel on an exchange: its word, and the client token
//	             if the serving side asks for one
//
// The serving side of the tunnel decides where a connection finally lands,
// so the proxy only opens a stream. Everything else a rule does (passing TLS
// through, terminating it with a plaintext or TLS upstream, the PROXY
// protocol header, speed limits) runs over that stream as over a TCP socket.
// The serving side may itself use QUIC or WebSockets: the hub joins the two.
//
// One pfrelay.Client per endpoint is kept across reloads while its settings
// (its exchange's included) stay the same. It holds one QUIC connection to
// the hub, made when first needed and again after it is lost, and each
// proxied connection is a stream on it.
//
// Only the connecting side is here: an exchange needs no serve token. One
// may be added later, for publishing this proxy's own listeners through a
// hub.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"maps"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/wushilin/pf-simple/pfrelay"
	"github.com/wushilin/pf-simple/pfrelayquic"
)

// relayScheme starts a rule's target that names an endpoint.
const relayScheme = "relay://"

// Exchange is one item of the exchanges section: a pf-simple relay hub.
type Exchange struct {
	Name   string
	Line   int
	Hub    string // the hub's https address, as written
	CAFile string // extra root CA for the hub's https; "" = system roots

	roots *x509.CertPool // CAFile's certificates
	caSum string         // CAFile's content, hashed: part of each endpoint's key
}

// Endpoint is one item of the endpoints section: a tunnel on an exchange.
type Endpoint struct {
	Name         string
	Line         int
	ExchangeName string
	Word         string // the tunnel's word, normalized (k3f9-x2mq-7hpa)
	ClientToken  string // "" = the tunnel asks for none

	exchange *Exchange
	key      string // every setting, the exchange's included: when a client can be kept
}

// Exchange is the hub the endpoint is on.
func (e *Endpoint) Exchange() *Exchange { return e.exchange }

// WordLabel is the word as logs and the console show it: its first group
// only, since whoever knows the word can connect.
func (e *Endpoint) WordLabel() string { return e.Word[:4] + "-…" }

// Describe is the endpoint for the console and logs, without its secrets.
func (e *Endpoint) Describe() string {
	s := fmt.Sprintf("exchange %s (%s), word %s", e.ExchangeName, e.exchange.Hub, e.WordLabel())
	if e.ClientToken != "" {
		s += ", client token"
	}
	return s
}

// checkExchange validates an exchanges item, and reads its CA.
func checkExchange(x *Exchange) error {
	if x.Hub == "" {
		return fmt.Errorf("hub is required: the pf-simple hub's https address, e.g. https://relay.example.com/")
	}
	// The SDK's own check of the address: https only, the console's /pf path
	// allowed. The client made here is dropped; no connection is opened.
	c, err := pfrelay.NewClient(x.Hub, "abcd-efgh-jkmn", nil)
	if err != nil {
		return fmt.Errorf("hub: %v", err)
	}
	c.Close()
	var caPEM []byte
	if x.CAFile != "" {
		if caPEM, err = os.ReadFile(x.CAFile); err != nil {
			return fmt.Errorf("ca_file: %v", err)
		}
		x.roots = x509.NewCertPool()
		if !x.roots.AppendCertsFromPEM(caPEM) {
			return fmt.Errorf("ca_file %s holds no PEM certificate", x.CAFile)
		}
	}
	sum := sha256.Sum256(caPEM)
	x.caSum = hex.EncodeToString(sum[:])
	return nil
}

// tlsConfig is what the hub's https is checked with: nil for the system
// roots.
func (x *Exchange) tlsConfig() *tls.Config {
	if x.roots == nil {
		return nil
	}
	return &tls.Config{RootCAs: x.roots, MinVersion: tls.VersionTLS12}
}

// checkEndpoint validates an endpoints item against the exchanges.
func checkEndpoint(e *Endpoint, exchanges map[string]*Exchange) error {
	if e.ExchangeName == "" {
		return fmt.Errorf("exchange is required: the name of an exchanges item (%s)", namesOr(exchanges, "there are none"))
	}
	if e.exchange = exchanges[e.ExchangeName]; e.exchange == nil {
		return fmt.Errorf("exchange %s: there is no exchanges item of that name (%s)", e.ExchangeName, namesOr(exchanges, "there are none"))
	}
	if e.Word == "" {
		return fmt.Errorf("word is required: the tunnel's word, e.g. k3f9-x2mq-7hpa")
	}
	word, err := pfrelay.NormalizeWord(e.Word)
	if err != nil {
		return fmt.Errorf("word: %v", err)
	}
	e.Word = word
	if e.ClientToken != "" {
		if err := pfrelay.CheckClientToken(e.ClientToken); err != nil {
			return fmt.Errorf("client_token: %v", err)
		}
	}
	x := e.exchange
	e.key = strings.Join([]string{x.Hub, x.caSum, e.Word, e.ClientToken}, "\x00")
	return nil
}

// namesOr lists m's names, sorted, or says none.
func namesOr[T any](m map[string]T, none string) string {
	if len(m) == 0 {
		return none
	}
	return strings.Join(slices.Sorted(maps.Keys(m)), ", ")
}

// resolveRelays indexes the exchanges and endpoints by name and points each
// relay rule at its endpoint.
func (c *Config) resolveRelays(exchanges []*Exchange, endpoints []*Endpoint) error {
	c.Exchanges, c.Endpoints = map[string]*Exchange{}, map[string]*Endpoint{}
	for _, x := range exchanges {
		if prev := c.Exchanges[x.Name]; prev != nil {
			return fmt.Errorf("line %d: exchange %s is already defined at line %d", x.Line, x.Name, prev.Line)
		}
		if err := checkExchange(x); err != nil {
			return fmt.Errorf("line %d: exchange %s: %v", x.Line, x.Name, err)
		}
		c.Exchanges[x.Name] = x
	}
	for _, e := range endpoints {
		if prev := c.Endpoints[e.Name]; prev != nil {
			return fmt.Errorf("line %d: endpoint %s is already defined at line %d", e.Line, e.Name, prev.Line)
		}
		if err := checkEndpoint(e, c.Exchanges); err != nil {
			return fmt.Errorf("line %d: endpoint %s: %v", e.Line, e.Name, err)
		}
		c.Endpoints[e.Name] = e
	}
	for i := range c.Rules {
		rule := &c.Rules[i]
		if rule.EndpointName == "" {
			continue
		}
		if rule.endpoint = c.Endpoints[rule.EndpointName]; rule.endpoint == nil {
			return fmt.Errorf("rule at line %d: target %s%s: there is no endpoint named %s (endpoints: %s)", rule.Line, relayScheme, rule.EndpointName, rule.EndpointName, namesOr(c.Endpoints, "none"))
		}
	}
	return nil
}

// relayPool keeps one client per endpoint (Endpoint.key), across reloads.
type relayPool struct {
	mu      sync.Mutex
	clients map[string]*relayClient
	agent   string // what the hub's console calls this proxy
}

type relayClient struct {
	c       *pfrelay.Client
	active  int  // connections open on it
	retired bool // no longer in the configuration: closed once active is 0
}

func newRelayPool() *relayPool {
	return &relayPool{clients: map[string]*relayClient{}, agent: "tlsproxy " + version}
}

// client returns the tunnel's client, making it the first time.
func (p *relayPool) client(e *Endpoint) (*relayClient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if rc := p.clients[e.key]; rc != nil {
		rc.retired = false // back in a configuration
		return rc, nil
	}
	c, err := newEndpointClient(e, p.agent)
	if err != nil {
		return nil, err
	}
	rc := &relayClient{c: c}
	p.clients[e.key] = rc
	return rc, nil
}

// newEndpointClient is a client of e's tunnel, over QUIC.
func newEndpointClient(e *Endpoint, agent string) (*pfrelay.Client, error) {
	c, err := pfrelayquic.NewClient(e.exchange.Hub, e.Word, e.exchange.tlsConfig())
	if err != nil {
		return nil, err
	}
	c.ClientToken, c.Agent = e.ClientToken, agent
	name := e.Name
	c.Logf = func(format string, args ...any) { logf("endpoint %s: %s", name, fmt.Sprintf(format, args...)) }
	return c, nil
}

// active is how many connections are open through e now.
func (p *relayPool) active(e *Endpoint) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if rc := p.clients[e.key]; rc != nil {
		return rc.active
	}
	return 0
}

// dial opens one connection through e's tunnel. The hub answers before the
// serving side has: if that side cannot reach its target, the first Read
// fails with the reason (a *pfrelay.RemoteError).
func (p *relayPool) dial(e *Endpoint, timeout time.Duration) (*relayConn, error) {
	rc, err := p.client(e)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	rc.active++
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := rc.c.Dial(ctx)
	if err != nil {
		p.release(rc)
		if ctx.Err() != nil {
			return nil, fmt.Errorf("endpoint %s: no answer from the hub within %s", e.Name, humanDuration(timeout))
		}
		return nil, fmt.Errorf("endpoint %s: %v", e.Name, err)
	}
	return &relayConn{Conn: conn, release: func() { p.release(rc) }}, nil
}

func (p *relayPool) release(rc *relayClient) {
	p.mu.Lock()
	rc.active--
	closeNow := rc.retired && rc.active == 0
	p.mu.Unlock()
	if closeNow {
		p.close(rc)
	}
}

// close ends a client that is no longer in the pool.
func (p *relayPool) close(rc *relayClient) {
	p.mu.Lock()
	for k, v := range p.clients {
		if v == rc {
			delete(p.clients, k)
		}
	}
	p.mu.Unlock()
	rc.c.Close()
}

// sync retires the clients of tunnels cfg no longer has: each is closed once
// its last connection ends, so a reload never cuts a connection.
func (p *relayPool) sync(cfg *Config) {
	keep := map[string]bool{}
	for _, e := range cfg.Endpoints {
		keep[e.key] = true
	}
	var idle []*relayClient
	p.mu.Lock()
	for k, rc := range p.clients {
		if keep[k] {
			continue
		}
		rc.retired = true
		if rc.active == 0 {
			idle = append(idle, rc)
		}
	}
	p.mu.Unlock()
	for _, rc := range idle {
		p.close(rc)
	}
}

// closeAll ends every client, and with them their connections.
func (p *relayPool) closeAll() {
	p.mu.Lock()
	all := p.clients
	p.clients = map[string]*relayClient{}
	p.mu.Unlock()
	for _, rc := range all {
		rc.c.Close()
	}
}

// relayConn is a connection through a tunnel, which gives its client back
// to the pool when closed.
type relayConn struct {
	*pfrelay.Conn
	once    sync.Once
	release func()
}

var _ duplex = (*relayConn)(nil)

func (c *relayConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// Peer is what the console and logs show as the connection's peer: the
// hub's QUIC address and the hub's id of the connection.
func (c *relayConn) Peer() string {
	return fmt.Sprintf("%s conn %s", c.RemoteAddr(), c.ID().Short())
}

// Target is where a decision connects: host:port, or relay://<name>.
func (d Decision) Target() string {
	if d.Rule != nil && d.Rule.EndpointName != "" {
		return relayScheme + d.Rule.EndpointName
	}
	return net.JoinHostPort(d.Host, fmt.Sprint(d.Port))
}

// TargetString is a rule's target as written: host:port (with ${1}... still
// in it), or relay://<name>.
func (r *Rule) TargetString() string {
	if r.EndpointName != "" {
		return relayScheme + r.EndpointName
	}
	return net.JoinHostPort(r.TargetHost, fmt.Sprint(r.TargetPort))
}
