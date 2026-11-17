// Package relayhook lets a transport other than WebSocket drive a
// pfrelay.Client: pfrelayquic attaches its QUIC transport here, and the
// Client keeps everything else (listeners, retries, reasons, events, stats).
// pfrelay itself never imports a QUIC library.
package relayhook

import (
	"context"
	"crypto/tls"

	"github.com/wushilin/pf-simple/internal/tunnel"
)

// Params are what a transport needs of the Client, read at each call.
type Params struct {
	Base        string // https://host[:port]/prefix, the hub's endpoints under Base + tunnel.APIPath
	Word        string
	ServeToken  string
	Name        string
	ClientToken string
	Agent       string
	TLS         *tls.Config // for the HTTPS endpoint, as the Client has it
	Logf        func(format string, args ...any)
}

// Transport is a way to reach the hub. Refusals come back as
// *tunnel.StatusError (with the hub's chosen protocol in its Header) and a
// hub too old for the transport as *tunnel.ProtoError, as over WebSocket.
type Transport interface {
	// Register registers the tunnel, returning once it is registered.
	Register(ctx context.Context, p Params, target string) (Registration, error)
	// Connect opens one connection, and returns its stream and id.
	Connect(ctx context.Context, p Params) (*tunnel.Stream, string, error)
	// Check asks whether the tunnel can be reached.
	Check(ctx context.Context, p Params) error
	// Close releases what the transport keeps between requests.
	Close() error
}

// Registration is one registration, until it ends.
type Registration interface {
	// Next waits for the hub's next request for a connection. Its error is
	// why the registration ended.
	Next(ctx context.Context) (Open, error)
	// Close ends the registration.
	Close()
}

// Open is the hub asking for one connection.
type Open interface {
	ID() string
	// Accept takes the connection: its stream.
	Accept(ctx context.Context) (*tunnel.Stream, error)
	// Refuse tells the hub why this side cannot carry it.
	Refuse(reason string)
}

// Attach is set by pfrelay: it makes client, a *pfrelay.Client, use t.
var Attach func(client any, t Transport)
