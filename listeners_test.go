package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestListenerConfig(t *testing.T) {
	// One listener: rules without listener = belong to it.
	c := mustParse(t, "[[listener]]\nname=https\nbind=127.0.0.1\nport=443\n[[host]]\npattern=a.test\ntarget_host=x\n")
	if len(c.Listeners) != 1 || c.Listeners[0].Name != "https" || c.Listeners[0].Line != 1 || c.Rules[0].Listener != "https" {
		t.Fatalf("%+v", c.Listeners)
	}

	// Two listeners: the same pattern on each is fine, each routes its own.
	two := "[global]\nidle_timeout=100\n" +
		"[[listener]]\nname=public\nport=443\n" +
		"[[listener]]\nname=lab\nbind=10.0.0.1; ::1\nport=9092\nidle_timeout=5\nmax_connections=3\nproxy_protocol_from=10.0.0.0/8\nmax_aggregated_speed=1Gbit\n" +
		"[[host]]\nlistener=public\npattern=ANY\ntarget_host=pub\n" +
		"[[host]]\nlistener=lab\npattern=ANY\ntarget_host=lab\n"
	c = mustParse(t, two)
	lab := c.Listener("lab")
	if lab == nil || lab.Port != 9092 || lab.Bind != "10.0.0.1; ::1" || lab.MaxConnections != 3 || lab.MaxAggregatedSpeed != 125e6 {
		t.Fatalf("%+v", lab)
	}
	eff := c.ForListener(lab)
	if eff.IdleTimeout != 5*time.Second || c.ForListener(c.Listener("public")).IdleTimeout != 100*time.Second || len(eff.ProxyProtocolFrom) != 1 {
		t.Fatal("overrides")
	}
	if d := eff.Route("x.test"); d.Host != "lab" {
		t.Fatal(d)
	}
	if d := c.ForListener(c.Listener("public")).Route("x.test"); d.Host != "pub" {
		t.Fatal(d)
	}
	if c.Rules[0].Key() == c.Rules[1].Key() {
		t.Fatal("rule keys must differ across listeners")
	}

	base := "[[listener]]\nname=a\nport=1\n[[listener]]\nname=b\nport=2\n"
	for text, want := range map[string]string{
		base + "[[host]]\npattern=x.test\ntarget_host=x\n":                            "listener = <name> is required: this file has 2 listeners (a, b)",
		base + "[[host]]\nlistener=c\npattern=x.test\ntarget_host=x\n":                "there is no [[listener]] named c",
		"[global]\nport=443\n" + base:                                                 "[global] port is no longer supported",
		"[global]\nbind=0.0.0.0\n" + base:                                             "[global] bind is no longer supported",
		"[global]\nport=443\n[[host]]\npattern=ANY\ntarget_host=x\n":                  "[global] port is no longer supported",
		"[global]\n[[host]]\npattern=ANY\ntarget_host=x\n":                            "no [[listener]] section",
		"[[listener]]\nname=a\nport=1\n[[listener]]\nname=a\nport=2\n":                "the name a is already used",
		"[[listener]]\nname=a\nport=1\n[[listener]]\nname=b\nbind=10.0.0.1\nport=1\n": "overlaps a",
		"[[listener]]\nname=Bad/Name\nport=1\n":                                       "name must be",
		"[[listener]]\nname=a\n":                                                      "port is required",
		"[[listener]]\nname=a\nport=1\nfoo=1\n":                                       `unknown key "foo" in [[listener]]`,
	} {
		_, err := ParseConfig(text)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", text, err, want)
		}
	}
}

// Two listeners at once; a reload adds, moves and removes ports live; Stop
// and Start close and reopen one; max_connections applies per listener.
func TestLiveListeners(t *testing.T) {
	t.Parallel()
	a, b := echoBackend(t, "A:"), echoBackend(t, "B:")
	path := filepath.Join(t.TempDir(), "config.toml")
	lab := freePort(t)
	write := func(listeners string) {
		text := "[global]\nstats_interval=0\nreload_interval=0\n" +
			"[[listener]]\nname=main\nport=1\n" + listeners +
			"[[host]]\nlistener=main\npattern=ANY\ntarget_host=127.0.0.1\ntarget_port=" + strconv.Itoa(a) + "\n"
		for _, name := range []string{"lab", "extra"} {
			if strings.Contains(listeners, "name="+name+"\n") {
				text += fmt.Sprintf("[[host]]\nlistener=%s\npattern=ANY\ntarget_host=127.0.0.1\ntarget_port=%d\n", name, b)
			}
		}
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	labSection := fmt.Sprintf("[[listener]]\nname=lab\nbind=127.0.0.1\nport=%d\nmax_connections=1\n", lab)
	write(labSection)
	text, _ := os.ReadFile(path)
	p := startProxyText(t, string(text), path)
	at := func(port int) *proxyUnderTest {
		return &proxyUnderTest{addr: fmt.Sprintf("127.0.0.1:%d", port), srv: p.srv}
	}
	roundtrip(t, p, "x.test", "A:")
	roundtrip(t, at(lab), "x.test", "B:")

	eventually := func(what string, ok func() bool) {
		t.Helper()
		for deadline := time.Now().Add(T); !ok(); time.Sleep(20 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal(what)
			}
		}
	}

	// max_connections = 1 on lab: a second connection is turned away.
	eventually("lab never idle", func() bool { return p.srv.stats.listener("lab").Active.Load() == 0 })
	held := dial(t, at(lab))
	held.Write(clientHello("held.test"))
	readN(t, held, 2)
	extra := dial(t, at(lab))
	if got := readToEnd(t, extra); len(got) != 0 {
		t.Fatalf("second connection served: %q", got)
	}
	held.Close()

	reload := func() {
		p.srv.reloadNow <- nil
	}
	refused := func(port int) bool {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			c.Close()
		}
		return err != nil
	}

	// Add a listener and move lab to another port, without a restart.
	extraPort, lab2 := freePort(t), freePort(t)
	write(fmt.Sprintf("[[listener]]\nname=lab\nbind=127.0.0.1\nport=%d\n[[listener]]\nname=extra\nbind=127.0.0.1\nport=%d\n", lab2, extraPort))
	reload()
	eventually("extra never opened", func() bool { return !refused(extraPort) })
	eventually("lab never moved", func() bool { return refused(lab) && !refused(lab2) })
	roundtrip(t, at(extraPort), "x.test", "B:")

	// Stop and start extra from the console's side.
	if err := p.srv.setListenerStopped("extra", true); err != nil {
		t.Fatal(err)
	}
	if !refused(extraPort) {
		t.Fatal("stopped listener still accepts")
	}
	if err := p.srv.setListenerStopped("extra", false); err != nil {
		t.Fatal(err)
	}
	roundtrip(t, at(extraPort), "x.test", "B:")

	// Remove both: their ports close, main carries on.
	write("")
	reload()
	eventually("removed listeners still open", func() bool { return refused(extraPort) && refused(lab2) })
	roundtrip(t, p, "x.test", "A:")
}

// The console adds a second listener: rules without listener = are tagged
// with the first one's name, and the new port opens.
func TestConsoleAddsListener(t *testing.T) {
	t.Parallel()
	a := echoBackend(t, "A:")
	_, c, path := startConsoleProxy(t, "password = pw", "[[host]]\npattern = ANY\ntarget_host = 127.0.0.1\ntarget_port = "+strconv.Itoa(a)+"\n")
	if c.login("pw") != 200 {
		t.Fatal("login")
	}
	port := freePort(t)
	_, st := c.get("/api/state")
	f := st["file"].(map[string]any)
	vals := map[string]string{"name": "lab", "bind": "127.0.0.1", "port": strconv.Itoa(port)}
	_, out := c.post("/api/listeners/validate", map[string]any{"line": 0, "values": vals})
	if out["ok"] != true || !strings.Contains(out["block"].(string), "name = lab") || len(out["notes"].([]any)) != 1 {
		t.Fatal(out)
	}
	if code, out := c.post("/api/listeners/save", map[string]any{"line": 0, "baseHash": f["hash"], "baseMtime": f["mtime"], "values": vals}); code != 200 || out["ok"] != true {
		t.Fatal(code, out)
	}
	text, _ := os.ReadFile(path)
	for _, want := range []string{"[[listener]]\nname=default\nport=1\n", "\n[[listener]]\nname = lab\nbind = 127.0.0.1\nport = " + strconv.Itoa(port), "[[host]]\nlistener = default\npattern = ANY"} {
		if !strings.Contains(string(text), want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
	// The new listener has no rules: everything on it is denied, but it is open.
	for deadline := time.Now().Add(T); ; time.Sleep(20 * time.Millisecond) {
		if conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("new listener never opened")
		}
	}
	// It cannot be deleted while a rule uses it.
	_, st = c.get("/api/state")
	f = st["file"].(map[string]any)
	var defLine float64
	for _, l := range st["listeners"].([]any) {
		if l := l.(map[string]any); l["name"] == "default" {
			defLine = l["line"].(float64)
		}
	}
	if _, out := c.post("/api/listeners/delete", map[string]any{"line": defLine, "baseHash": f["hash"], "baseMtime": f["mtime"]}); out["ok"] != false || !strings.Contains(out["error"].(string), "still has 1 rule") {
		t.Fatal(out)
	}
}

// Listener names may use spaces and punctuation; written by the console they
// are quoted, and rules refer to them the same way.
func TestListenerNames(t *testing.T) {
	for _, name := range []string{"Kafka (EU)", `a"b'c`, "#1 <tls> [x]", "~@_-", "A"} {
		q, err := fmtValue(name)
		if err != nil {
			t.Fatal(err)
		}
		text := "[[listener]]\nname = " + q + "\nport = 1\n[[host]]\nlistener = " + q + "\npattern = a.com\ntarget_host = b\n" +
			"[[listener]]\nname = other\nport = 2\n"
		cfg, err := ParseConfig(text)
		if err != nil {
			t.Errorf("%q: %v", name, err)
			continue
		}
		if cfg.Listeners[0].Name != name || cfg.Rules[0].Listener != name {
			t.Errorf("%q: parsed as %q, rule %q", name, cfg.Listeners[0].Name, cfg.Rules[0].Listener)
		}
	}
	for _, bad := range []string{" lead", "trail ", "a/b", "a:b", "a.b", "a\\b", "é", strings.Repeat("x", 65)} {
		q, _ := fmtValue(bad)
		if _, err := ParseConfig("[[listener]]\nname = " + q + "\nport = 1\n"); err == nil || !strings.Contains(err.Error(), "name must be") {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
	if _, err := ParseConfig("[[listener]]\nname = Web\nport = 1\n[[listener]]\nname = web\nport = 2\n"); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Errorf("names differing only in case: %v", err)
	}
}

// A port that cannot be opened at start-up does not keep the other
// listeners down: it is reported, shown with its error, and Start retries it.
func TestStartupWithABusyPort(t *testing.T) {
	t.Parallel()
	busy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	busyPort := busy.Addr().(*net.TCPAddr).Port
	free := freePort(t)
	cfg, err := ParseConfig(fmt.Sprintf("[[listener]]\nname=ok\nbind=127.0.0.1\nport=%d\n[[listener]]\nname=taken\nbind=127.0.0.1\nport=%d\n"+
		"[[host]]\nlistener=ok\npattern=ANY\naction=deny\n", free, busyPort))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		srv.listenersMu.Lock()
		for _, l := range srv.listeners {
			l.close()
		}
		srv.listenersMu.Unlock()
	}()
	failed := srv.syncListeners(cfg)
	if len(failed) != 1 || !strings.Contains(failed[0], "listener taken: cannot listen on 127.0.0.1:") {
		t.Fatalf("failed: %v", failed)
	}
	if _, open, _, _ := srv.listenerState("ok"); !open {
		t.Fatal("the other listener is not open")
	}
	if _, open, stopped, msg := srv.listenerState("taken"); open || stopped || msg == "" {
		t.Fatalf("taken: open=%v stopped=%v err=%q", open, stopped, msg)
	}
	// Start fails while the port is taken and leaves it as it was; once
	// the port is free, Start opens it.
	if err := srv.setListenerStopped("taken", false); err == nil {
		t.Fatal("Start succeeded on a taken port")
	}
	if err := srv.setListenerStopped("taken", true); err != nil {
		t.Fatal(err)
	}
	if err := srv.setListenerStopped("taken", false); err == nil {
		t.Fatal("Start succeeded on a taken port")
	}
	if _, _, stopped, msg := srv.listenerState("taken"); !stopped || msg == "" {
		t.Fatalf("a failed Start must leave it stopped, with the error: stopped=%v err=%q", stopped, msg)
	}
	busy.Close()
	if err := srv.setListenerStopped("taken", false); err != nil {
		t.Fatal(err)
	}
	if _, open, stopped, msg := srv.listenerState("taken"); !open || stopped || msg != "" {
		t.Fatalf("after Start: open=%v stopped=%v err=%q", open, stopped, msg)
	}
}

// A rule without target_port connects to the port its listener listens on.
func TestTargetPortDefaultsToListenerPort(t *testing.T) {
	c := mustParse(t, "[[listener]]\nname=https\nport=443\n[[listener]]\nname=kafka\nport=9092\n"+
		"[[host]]\nlistener=https\npattern=ANY\ntarget_host=${host}\n"+
		"[[host]]\nlistener=kafka\npattern=ANY\ntarget_host=${host}\n"+
		"[[host]]\nlistener=kafka\npattern=b.test\ntarget_host=b\ntarget_port=19092\n")
	for l, want := range map[string]string{"https": "a.test:443", "kafka": "a.test:9092"} {
		if got := route(t, c.ForListener(c.Listener(l)), "a.test"); got != want {
			t.Errorf("%s: %s, want %s", l, got, want)
		}
	}
	if got := route(t, c.ForListener(c.Listener("kafka")), "b.test"); got != "b:19092" {
		t.Errorf("explicit target_port: %s", got)
	}
}
