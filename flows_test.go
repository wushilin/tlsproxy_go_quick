package main

import (
	"crypto/tls"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The flow log shows connections too short to appear in a state frame: each
// one opens and closes with its outcome, and a page opened later starts with
// the history.
func TestFlowLog(t *testing.T) {
	t.Parallel()
	p, c, _ := startConsoleProxy(t, "password = pw", fmt.Sprintf(
		"[[host]]\npattern=ok.flow.test\ntarget_host=127.0.0.1\ntarget_port=%d\n[[host]]\npattern=no.flow.test\naction=deny\n", echoBackend(t, "F:")))
	c.login("pw")
	next := wsFramesAt(t, c, "/api/flows")
	if first := next(); first["type"] != "snapshot" || first["full"] != true {
		t.Fatal(first)
	}

	roundtrip(t, p, "ok.flow.test", "F:")
	conn := dial(t, p)
	conn.Write(clientHello("no.flow.test"))
	readToEnd(t, conn)

	ended := map[string]map[string]any{} // sni -> close event's flow
	opened := map[float64]bool{}
	lastSeq := map[float64]float64{} // id -> seq of its latest event: they only go up
	for deadline := time.Now().Add(T); len(ended) < 2; {
		if time.Now().After(deadline) {
			t.Fatalf("closed: %v", ended)
		}
		m := next()
		if m["type"] != "events" {
			continue
		}
		for _, e := range m["events"].([]any) {
			ev := e.(map[string]any)
			f := ev["flow"].(map[string]any)
			id, seq := f["id"].(float64), f["seq"].(float64)
			if seq <= lastSeq[id] {
				t.Errorf("#%v: %s event with seq %v after %v", id, ev["type"], seq, lastSeq[id])
			}
			lastSeq[id] = seq
			switch ev["type"] {
			case "open":
				opened[f["id"].(float64)] = true
			case "close":
				if !opened[f["id"].(float64)] {
					t.Errorf("closed before it opened: %v", f)
				}
				ended[f["sni"].(string)] = f
			}
		}
	}
	if f := ended["ok.flow.test"]; f["result"] != flowClosed || f["rule"] != "ok.flow.test" || f["bytesDown"].(float64) == 0 || f["ended"].(float64) < f["started"].(float64) {
		t.Errorf("relayed: %v", f)
	}
	if f := ended["no.flow.test"]; f["result"] != flowDenied || f["reason"] == "" {
		t.Errorf("denied: %v", f)
	}
	// How it was handled: passed through, spliced on Linux, no PROXY header.
	wantRelay := "copy"
	if runtime.GOOS == "linux" {
		wantRelay = "splice"
	}
	if f := ended["ok.flow.test"]; f["tls"] != "passthrough" || f["relay"] != wantRelay || f["proxyOut"] != nil {
		t.Errorf("handling: tls=%v relay=%v proxyOut=%v", f["tls"], f["relay"], f["proxyOut"])
	}

	// A page opened now starts with both in its recent history; one closed a
	// minute ago only comes with history=all.
	old := time.Now().Add(-time.Minute).UnixMilli()
	p.srv.stats.flows.record(flowView{ID: 1 << 40, Seq: flowSeq.Add(1), Listener: "default", SNI: "old.flow.test", Routed: true,
		Started: old - 1000, Ended: old, Result: flowClosed})
	hasOld := func(m map[string]any) bool {
		for _, f := range m["closed"].([]any) {
			if f.(map[string]any)["sni"] == "old.flow.test" {
				return true
			}
		}
		return false
	}
	if all := wsFramesAt(t, c, "/api/flows?history=all")(); !hasOld(all) {
		t.Fatal("history=all lacks the old connection")
	}
	first := wsFramesAt(t, c, "/api/flows")()
	if hasOld(first) {
		t.Fatal("the default history should only hold the last 35 s")
	}
	seen := 0
	for _, f := range first["closed"].([]any) {
		if sni := f.(map[string]any)["sni"]; sni == "ok.flow.test" || sni == "no.flow.test" {
			seen++
		}
	}
	if seen != 2 {
		t.Fatalf("history: %v", first["closed"])
	}
}

// flowFor waits for the closed connection to sni to reach the flow history.
func flowFor(t *testing.T, p *proxyUnderTest, sni string) flowView {
	t.Helper()
	for deadline := time.Now().Add(T); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		for _, f := range p.srv.stats.flows.closedSince(0) {
			if f.SNI == sni {
				return f
			}
		}
	}
	t.Fatalf("no closed flow for %s", sni)
	return flowView{}
}

// The flow log says how each connection was handled: the load balancer in
// front, the PROXY header sent on, termination and what the target speaks.
func TestFlowHandlingDetails(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	port := echoBackend(t, "up:")
	p := startProxy(t, "proxy_protocol_from = 127.0.0.1",
		fmt.Sprintf("[[host]]\npattern=via.flow.test\nproxy=true\nproxy_version=1\nmax_single_connection_speed=1MiB/s\ntarget_host=127.0.0.1\ntarget_port=%d\n", port)+
			fmt.Sprintf("[[host]]\npattern=term.flow.test\ncert=%s\nupstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=%d\n", ca.localCA(t), port))

	// A load balancer (this test) sends a PROXY v2 header; the rule sends v1 on.
	c := dial(t, p)
	v4 := []byte{203, 0, 113, 9, 127, 0, 0, 1, 0x9c, 0x40, 0x01, 0xbb}
	c.Write(append(proxyV2Header(0x11, v4), clientHello("via.flow.test")...))
	readN(t, c, len("up:"))
	c.Close()
	f := flowFor(t, p, "via.flow.test")
	if f.ViaVersion != 2 || !strings.HasPrefix(f.Via, "127.0.0.1:") || f.Src != "203.0.113.9:40000" || f.ProxyOut != 1 || f.TLS != "passthrough" || f.ConnLimit != 1<<20 {
		t.Errorf("via: %+v", f.flowHow)
	}

	// Terminated, plaintext to the target.
	tc, err := tlsDial(t, p, &tls.Config{RootCAs: ca.pool, ServerName: "term.flow.test", NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	tc.Write([]byte("x"))
	readN(t, tc, len("up:x"))
	tc.Close()
	f = flowFor(t, p, "term.flow.test")
	if f.TLS != "terminated" || f.ClientTLS != "TLS 1.3" || f.Upstream != "plain" || f.Relay != "copy" || f.ProxyOut != 0 {
		t.Errorf("terminated: %+v", f.flowHow)
	}
}
