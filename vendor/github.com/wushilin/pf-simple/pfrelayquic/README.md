# pfrelayquic

The Go SDK for the [pf-simple](https://github.com/wushilin/pf-simple) relay
hub over QUIC (tunnel protocol 3, [`docs/PROTOCOL.md`](../docs/PROTOCOL.md)
§13). It serves a tunnel, or connects through one, from your own program,
as `pf-client-quic` does.

`pfrelayquic.NewClient` returns the same `*pfrelay.Client` as
[`pfrelay`](../pfrelay), the WebSocket SDK, so the whole API is pfrelay's:
`Listen` and `Dial`, `Serve` and `Connect`, `Check` and `Watch`, events,
stats, connection ids and `Drop`. Only the way to the hub differs. Moving a
program from WebSockets to QUIC means changing the constructor:

```go
import "github.com/wushilin/pf-simple/pfrelayquic"

// serve
c, err := pfrelayquic.NewClient("https://relay.example.com/", "k3f9-x2mq-7hpa", nil)
c.ServeToken, c.Name = os.Getenv("PF_SERVE_TOKEN"), "My service"
ln, err := c.Listen(ctx)    // a net.Listener of *pfrelay.Conn
http.Serve(ln, handler)

// connect
c, err := pfrelayquic.NewClient("https://relay.example.com/", "k3f9-x2mq-7hpa", nil)
conn, err := c.Dial(ctx)    // a net.Conn, plus CloseWrite, Fail and Err
```

How it reaches the hub:

- It asks the hub's https address (`/pf/api/tunnel/quic`) where its QUIC
  listener is, and which certificate it uses, with the credentials of the
  run: the serve token to serve, the word and client token to connect.
- It opens one QUIC connection to that address and trusts exactly the
  certificate announced, by its SHA-256. The https endpoint itself is
  verified as usual (`tlsConfig` in `NewClient`).
- Every request and every connection is a stream on that one QUIC
  connection, kept alive with a ping at least every 10 seconds. A lost
  connection is made again, through discovery, when next needed.

A QUIC client works with a WebSocket client on the other side of a tunnel:
the hub joins them. There is no fallback to WebSockets: where UDP is
blocked on the way, this fails to connect, and pfrelay is the one to use.
A hub older than pf-simple 0.16.0, or one whose QUIC listener is off, is
reported as such.

pfrelayquic is built on [quic-go](https://github.com/quic-go/quic-go), and
pfrelay does not import it: a program that uses only pfrelay does not carry
a QUIC library.

Licensed under the Apache License 2.0; see [LICENSE](LICENSE).
