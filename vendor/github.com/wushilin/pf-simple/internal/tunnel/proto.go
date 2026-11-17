package tunnel

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// The tunnel protocol has a version of its own, apart from the programs'
// versions, so that one pf-client works with servers of several ages and
// the other way round. Each side speaks a range of versions; they use the
// highest both have.
//
// Protocol 1 is SEALED. It is what pf-simple 0.14.0 speaks:
//
//   - serve: a word, a name and a target; a serve token, or none where the
//     server allows serving without one; optionally the SHA-256 of a
//     client token that whoever connects must give.
//   - connect and check: a word; the client token if the tunnel has one.
//   - accept: a word and a connection id, or the reason there is no
//     connection.
//   - version: a serve token; the answer is the server's program version
//     and the protocol range it speaks, as JSON (ServerInfo). It is the
//     only way to learn a server's version, and needs a valid serve token.
//   - the headers above, the WebSocket framing of ws.go and the "eof" and
//     "err:" text frames of stream.go.
//
// Nothing in protocol 1 may change: no header renamed, dropped or given a
// new meaning, no new header a peer must understand, no change to the
// frames. Whatever is added or changed goes into protocol 2, by the steps
// at the end of this comment, so that a side which only speaks 1 is told
// plainly instead of misunderstanding.
//
// Protocol 0 is the name for a side that does not announce a version:
// pf-simple and pf-client before 0.14.0. Such a side understands a word, a
// serve token, a name and a target, and may or may not do the rest of
// protocol 1 without saying so, so nothing beyond those is relied on with
// it. It is still spoken, for plain tunnels.
//
// The connecting or serving side sends the range it can use for this run
// in HeaderProto, as "min-max": min is raised to the version of the newest
// feature the run depends on, so a server that is too old for it says so
// instead of quietly ignoring the feature. The server answers every tunnel
// request, refused or not, with the version it chose in the same header,
// or with 426 and an explanation when the ranges do not meet. A server
// that sends no HeaderProto speaks protocol 0, and it is then for the
// client to refuse. The client sends its program's version in
// HeaderVersion, for the server's log and console only: nothing may be
// decided from it. The server does not send its own: it is not for
// whoever happens to reach the port, and is asked for with a serve token.
//
// Protocol 2 (pf-simple 0.15.0) adds one optional thing to protocol 1:
// reusing the serving side's accept legs. It is specified in full in
// docs/PROTOCOL.md §12. In short:
//
//   - serve: when protocol 2 was negotiated, the 101 carries a random
//     per-registration secret in HeaderSession.
//   - accept: a serving side that sends that secret back, on a request that
//     also negotiated protocol 2, may be offered reuse: the 101 carries
//     HeaderKeepAlive, the seconds an idle leg is kept.
//   - on an offered leg, after a clean finish the hub sends the text frame
//     "idle"; the client answers "idle" to keep the leg, or closes. A kept
//     leg is idle; the hub hands it the next connection with "bind <id>",
//     which the client answers at once with "bound <id>".
//
// Nothing else changes, and nothing is ever sent to a peer that did not
// negotiate protocol 2 and prove its registration. Nothing depends on
// reuse either: a side that does not get it carries on as in protocol 1.
//
// To add protocol N+1: raise ProtoMax; describe it here as protocol 1 is
// described; add it to protoRelease; give each new feature an entry in
// featureProto and have Client.needs (pfrelay/client.go) and the other
// SDKs name it; describe it in docs/PROTOCOL.md; make the server honor it
// only when the chosen version allows. Raise ProtoMin only to stop
// speaking to old peers, which is a decision for the project's owner.
const (
	HeaderProto   = "X-PF-Tunnel-Proto"
	HeaderVersion = "X-PF-Version"
	// Protocol 2: the registration's secret, and the offer of reuse.
	HeaderSession   = "X-PF-Tunnel-Session"
	HeaderKeepAlive = "X-PF-Tunnel-Keep-Alive"

	// The WebSocket endpoints speak protocols ProtoMin to ProtoMax.
	// Protocol 3 is the QUIC transport (docs/PROTOCOL.md): it is
	// spoken only over QUIC, and negotiated there (internal/quictun), so
	// it is not in this range.
	ProtoMin = 0
	ProtoMax = 2
)

// protoRelease is the first pf-simple release that speaks each protocol.
var protoRelease = map[int]string{0: "0.11.0", 1: "0.14.0", 2: "0.15.0"}

// Feature is something a run may depend on that not every protocol has.
type Feature int

const (
	FeatureClientToken Feature = iota
	FeatureAnonymousServe
	// FeatureReuse is reusing accept legs. Nothing ever depends on it, so
	// no request names it; it is listed for the record.
	FeatureReuse
)

var featureProto = map[Feature]struct {
	proto int
	name  string
}{
	FeatureClientToken:    {1, "a client token"},
	FeatureAnonymousServe: {1, "serving without a serve token"},
	FeatureReuse:          {2, "reusing accept legs"},
}

// ServerInfo is the answer to a version probe.
type ServerInfo struct {
	Version  string `json:"version"`  // the program's version, e.g. "0.14.0"
	ProtoMin int    `json:"protoMin"` // the tunnel protocols it speaks
	ProtoMax int    `json:"protoMax"`
	Token    string `json:"token"` // the name of the serve token that asked
}

// ProtoRange formats a range for HeaderProto.
func ProtoRange(min, max int) string { return strconv.Itoa(min) + "-" + strconv.Itoa(max) }

// ParseProtoRange reads HeaderProto as a peer sent it. An empty header is
// a peer that announces no version: protocol 0. A single number is a range
// of one.
func ParseProtoRange(s string) (min, max int, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, nil
	}
	lo, hi, isRange := strings.Cut(s, "-")
	if !isRange {
		hi = lo
	}
	min, err1 := strconv.Atoi(lo)
	max, err2 := strconv.Atoi(hi)
	if err1 != nil || err2 != nil || min < 0 || max < min || max > 1<<20 {
		return 0, 0, fmt.Errorf("invalid tunnel protocol range %q", s)
	}
	return min, max, nil
}

// Negotiate picks the protocol to use with a peer that speaks min to max:
// the highest both sides have. ok is false when they share none.
func Negotiate(min, max int) (proto int, ok bool) {
	proto = max
	if proto > ProtoMax {
		proto = ProtoMax
	}
	return proto, proto >= min && proto >= ProtoMin
}

// ProtoMismatch words the refusal when the ranges do not meet, from the
// server's point of view.
func ProtoMismatch(min, max int) string {
	if min > ProtoMax {
		return fmt.Sprintf("this server speaks tunnel protocol %s and this pf-client needs %s for what it was asked to do: upgrade the server to pf-simple %s or later, or use a pf-client of the server's age",
			ProtoRange(ProtoMin, ProtoMax), ProtoRange(min, max), releaseOf(min))
	}
	return fmt.Sprintf("this server speaks tunnel protocol %s and this pf-client only %s: use pf-client %s or later",
		ProtoRange(ProtoMin, ProtoMax), ProtoRange(min, max), releaseOf(ProtoMin))
}

func releaseOf(proto int) string {
	if r, ok := protoRelease[proto]; ok {
		return r
	}
	return "of a newer release"
}

// ProtoError is a server that is too old for what this run depends on.
// Trying again cannot help.
type ProtoError struct {
	Server int     // the protocol the server speaks
	Need   Feature // what was asked for
}

func (e *ProtoError) Error() string {
	f := featureProto[e.Need]
	speaks := fmt.Sprintf("it speaks tunnel protocol %d", e.Server)
	if e.Server == 0 {
		speaks = "it announces no tunnel protocol"
	}
	return fmt.Sprintf("this server is too old for %s: %s, and that needs protocol %d (pf-simple %s or later). Upgrade the server, or do without it",
		f.name, speaks, f.proto, releaseOf(f.proto))
}

// ServerProto reads the protocol a server chose from its response. One
// that says nothing speaks protocol 0.
func ServerProto(h http.Header) int {
	if n, err := strconv.Atoi(strings.TrimSpace(h.Get(HeaderProto))); err == nil && n >= 0 {
		return n
	}
	return 0
}

// FeatureProto is the protocol that first has f.
func FeatureProto(f Feature) int { return featureProto[f].proto }
