package main

// Access records: one line per connection, whatever happened to it (passed
// through, terminated, served, relayed, denied, rejected, an ACME challenge),
// and one per HTTP request this proxy answers itself. They are a stream of
// their own (logging.access), with the activity stream on stdout by default;
// each line names itself "access" so the two can be told apart there.
//
//	logfmt: 2026-11-19T08:01:02.345Z access kind=conn id=12 listener=https src=203.0.113.9:51234 sni=www.example.com result=closed mode=pass ...
//	json:   {"ts":"2026-11-19T08:01:02.345Z","log":"access","kind":"conn","id":12,...}
//
// Fields that do not apply are left out. Sizes are bytes and durations
// milliseconds, as plain numbers.

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

type accessField struct {
	key string
	val any // string, int64, uint64 or bool
}

type accessRecord []accessField

// str adds a text field, unless it is empty.
func (r accessRecord) str(k, v string) accessRecord {
	if v == "" {
		return r
	}
	return append(r, accessField{k, v})
}

// num adds a number field.
func (r accessRecord) num(k string, v int64) accessRecord {
	return append(r, accessField{k, v})
}

// line is the record as one line in the configured format.
func (r accessRecord) line(now time.Time) string {
	ts := now.UTC().Format("2006-01-02T15:04:05.000Z")
	var b strings.Builder
	if accessJSON.Load() {
		b.WriteString(`{"ts":"` + ts + `","log":"access"`)
		for _, f := range r {
			k, _ := json.Marshal(f.key)
			v, _ := json.Marshal(f.val)
			b.WriteByte(',')
			b.Write(k)
			b.WriteByte(':')
			b.Write(v)
		}
		b.WriteString("}\n")
		return b.String()
	}
	b.WriteString(ts + " access")
	for _, f := range r {
		b.WriteByte(' ')
		b.WriteString(f.key)
		b.WriteByte('=')
		switch v := f.val.(type) {
		case string:
			b.WriteString(logfmtValue(v))
		case int64:
			b.WriteString(strconv.FormatInt(v, 10))
		case uint64:
			b.WriteString(strconv.FormatUint(v, 10))
		case bool:
			b.WriteString(strconv.FormatBool(v))
		}
	}
	b.WriteByte('\n')
	return b.String()
}

// logfmtValue quotes v when it would not read back as one value: a space,
// a quote, an equals sign, a control character or nothing at all.
func logfmtValue(v string) string {
	if v == "" {
		return `""`
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c <= ' ' || c == '"' || c == '=' || c == '\\' || c >= 0x7f {
			return strconv.Quote(v)
		}
	}
	return v
}

// withTag starts a record with its kind and, if logging.access_tag is set,
// the node it came from.
func newAccessRecord(kind string) accessRecord {
	r := accessRecord{{"kind", kind}}
	if p := accessTagVal.Load(); p != nil && *p != "" {
		r = append(r, accessField{"node", *p})
	}
	return r
}

func writeAccess(r accessRecord) {
	if accessOff.Load() {
		return
	}
	emitLine(streamAccess, r.line(time.Now()))
}

// accessConn writes the access record of a connection that has ended.
func accessConn(v *flowView) {
	if accessOff.Load() {
		return
	}
	r := newAccessRecord("conn").
		num("id", int64(v.ID)).
		str("listener", v.Listener).
		str("src", v.Src).
		str("via", v.Via). // the load balancer that sent a PROXY header for src
		str("local", v.Local)
	if v.Routed {
		r = append(r, accessField{"sni", v.SNI}) // "" too: a client that sent no name
	}
	r = r.str("result", v.Result).
		str("mode", accessMode(v)).
		str("rule", v.Rule).
		str("dst", v.Dst).
		str("peer", v.Peer).
		str("client_tls", v.ClientTLS).
		str("alpn", v.ALPN).
		str("upstream", v.Upstream)
	if v.Resumed {
		r = append(r, accessField{"resumed", true})
	}
	if v.Ended == 0 {
		v.Ended = time.Now().UnixMilli()
	}
	r = r.num("up", v.BytesUp).
		num("down", v.BytesDown).
		num("dur_ms", max(0, v.Ended-v.Started)).
		str("reason", v.Reason)
	writeAccess(r)
}

// accessMode is how a connection was handled: pass (TLS passed through),
// terminate (TLS ended here, relayed on), serve (answered here), relay
// (through a tunnel endpoint), http (the port 80 redirect), or "" when it
// never got that far.
func accessMode(v *flowView) string {
	switch {
	case v.Result == flowRejected || v.Result == flowDenied || v.Result == flowACME:
		return ""
	case v.TLS == "http":
		return "http"
	case v.Dst == "served here":
		return "serve"
	case strings.HasPrefix(v.Dst, "relay://"):
		return "relay"
	case v.TLS == "terminated":
		return "terminate"
	case v.TLS == "passthrough":
		return "pass"
	}
	return ""
}

// accessRequest writes the access record of one HTTP request this proxy
// answered: served here, or the port 80 redirect.
func accessRequest(c *ConnState, method, host, uri, proto string, status int, bytes int64, d time.Duration, extra ...accessField) {
	if accessOff.Load() {
		return
	}
	r := newAccessRecord("http").
		num("id", int64(c.ID)).
		str("listener", c.Listener).
		str("src", c.Src).
		str("method", method).
		str("host", host).
		str("uri", uri).
		str("proto", proto).
		num("status", int64(status)).
		num("bytes", bytes).
		num("dur_ms", d.Milliseconds())
	for _, f := range extra {
		if s, ok := f.val.(string); !ok || s != "" {
			r = append(r, f)
		}
	}
	writeAccess(r)
}

// accessNote is a request's log note (" (listing)", " via serve 9 (index.html)")
// for its access record: without the space, and without the parentheses
// when they wrap all of it.
func accessNote(note string) string {
	note = strings.TrimSpace(note)
	if strings.HasPrefix(note, "(") && strings.HasSuffix(note, ")") && strings.Count(note, "(") == 1 {
		note = note[1 : len(note)-1]
	}
	return note
}
