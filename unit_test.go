package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------- helpers

// buildClientHello builds a minimal ClientHello handshake message (no record
// framing), optionally with a padding extension of pad bytes.
func buildClientHello(sni *string, pad int) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)                // session id
	body = append(body, 0, 2, 0x13, 0x01) // one cipher suite
	body = append(body, 1, 0)             // null compression
	exts := []byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04}
	if pad > 0 {
		exts = append(exts, 0x00, 0x15, byte(pad>>8), byte(pad))
		exts = append(exts, make([]byte, pad)...)
	}
	if sni != nil {
		h := []byte(*sni)
		entry := append([]byte{0, byte(len(h) >> 8), byte(len(h))}, h...)
		list := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
		exts = append(exts, 0, 0, byte(len(list)>>8), byte(len(list)))
		exts = append(exts, list...)
	}
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hs, body...)
}

// wrapRecords frames a handshake message into TLS records of at most chunk bytes.
func wrapRecords(hs []byte, chunk int) []byte {
	var out []byte
	for len(hs) > 0 {
		n := min(chunk, len(hs))
		out = append(out, 0x16, 0x03, 0x01, byte(n>>8), byte(n))
		out = append(out, hs[:n]...)
		hs = hs[n:]
	}
	return out
}

func clientHello(sni string) []byte { return wrapRecords(buildClientHello(&sni, 0), 16384) }

func hsWithBody(typ byte, body []byte) []byte {
	return append([]byte{typ, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

// ---------------------------------------------------------------- sni

func TestSNISingleRecord(t *testing.T) {
	sni, err := parseClientHello(clientHello("Foo.Wushilin.NET"))
	if err != nil || sni != "foo.wushilin.net" {
		t.Fatalf("%q %v", sni, err)
	}
}

func TestSNIFragmentedAndIncremental(t *testing.T) {
	name := "a.b.c"
	data := wrapRecords(buildClientHello(&name, 0), 7)
	// Every strict prefix needs more data; the full input parses.
	for i := 0; i < len(data); i++ {
		if _, err := parseClientHello(data[:i]); err != errNeedMore {
			t.Fatalf("prefix %d: %v", i, err)
		}
	}
	if sni, err := parseClientHello(data); err != nil || sni != name {
		t.Fatalf("%q %v", sni, err)
	}
	// Trailing application data after the hello is fine.
	if sni, err := parseClientHello(append(data, "\x17\x03\x03 extra"...)); err != nil || sni != name {
		t.Fatalf("%q %v", sni, err)
	}
}

func TestSNILargePostQuantumHello(t *testing.T) {
	for _, pad := range []int{1800, 30000} {
		name := "pq.example.com"
		sni, err := parseClientHello(wrapRecords(buildClientHello(&name, pad), 16384))
		if err != nil || sni != name {
			t.Fatalf("pad %d: %q %v", pad, sni, err)
		}
	}
}

func TestSNIAbsent(t *testing.T) {
	if sni, err := parseClientHello(wrapRecords(buildClientHello(nil, 0), 16384)); err != nil || sni != "" {
		t.Fatalf("%q %v", sni, err)
	}
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0) // no extensions block at all
	if sni, err := parseClientHello(wrapRecords(hsWithBody(1, body), 16384)); err != nil || sni != "" {
		t.Fatalf("%q %v", sni, err)
	}
}

func TestSNIRejects(t *testing.T) {
	oversized := append([]byte{0x01, 0x01, 0x86, 0xa0}, make([]byte, 100)...) // claims 100000 bytes
	name := "a.b"
	corrupt := buildClientHello(&name, 0)
	corrupt[len(corrupt)-9] = 0xff // server_name extension length overruns
	cases := map[string][]byte{
		"http":         []byte("GET / HTTP/1.1\r\n\r\n"),
		"ssh":          []byte("SSH-2.0-OpenSSH_9.0\r\n"),
		"alert":        {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28},
		"sslv2":        {0x16, 0x02, 0x00, 0x00, 0x01, 0x01},
		"empty record": {0x16, 0x03, 0x01, 0x00, 0x00},
		"server hello": wrapRecords(hsWithBody(2, make([]byte, 40)), 16384),
		"oversized":    wrapRecords(oversized, 16384),
		"short body":   wrapRecords(hsWithBody(1, []byte{3, 3, 0, 0}), 16384),
		"corrupt ext":  wrapRecords(corrupt, 16384),
	}
	for _, bad := range []string{"a b.com", "a/b", "x\x00y", "é.com"} {
		bad := bad
		cases["sni "+bad] = wrapRecords(buildClientHello(&bad, 0), 16384)
	}
	for name, data := range cases {
		if _, err := parseClientHello(data); err == nil || err == errNeedMore {
			t.Errorf("%s: expected rejection, got %v", name, err)
		}
	}
}

// ---------------------------------------------------------------- config

const sampleConfig = `
[global]
bind=0.0.0.0
port=8443   # listen port

[[host]]
pattern=(.*).wushilin.net
action=allow
target_host=$1.wushilin.internal.net
target_port=443

[[host]]
pattern = '(.*)\.example\.com'
target_host = "backend-${1}.lan"

[[host]]
pattern=.*
action=deny
`

func route(t *testing.T, c *Config, sni string) string {
	t.Helper()
	d := c.Route(sni)
	switch {
	case d.Err != "":
		return "ERROR"
	case d.Allow:
		return fmt.Sprintf("%s:%d", d.Host, d.Port)
	}
	return "DENY"
}

func mustParse(t *testing.T, text string) *Config {
	t.Helper()
	c, err := ParseConfig(text)
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	return c
}

func TestConfigSample(t *testing.T) {
	c := mustParse(t, sampleConfig)
	if c.Port != 8443 || len(c.Rules) != 3 {
		t.Fatalf("%+v", c)
	}
	for sni, want := range map[string]string{
		"foo.wushilin.net":          "foo.wushilin.internal.net:443",
		"a.b.wushilin.net":          "a.b.wushilin.internal.net:443",
		"api.example.com":           "backend-api.lan:443",
		"google.com":                "DENY",
		"":                          "DENY",
		"foo.wushilin.net.evil.com": "DENY", // must match the whole name
	} {
		if got := route(t, c, sni); got != want {
			t.Errorf("%q: got %s want %s", sni, got, want)
		}
	}
}

func TestConfigDefaultsAndValueForms(t *testing.T) {
	c := mustParse(t, "[global]\r\nport = \"8443\" # quoted number\r\nidle_timeout = 0\r\n"+
		"[[host]]\r\npattern = \"(.*)\\.a\\.com\"  # comment\r\ntarget_host = '$1.b'\r\n")
	if c.Bind != "0.0.0.0" || c.IdleTimeout != 0 || c.HandshakeTimeout != 10*time.Second ||
		c.HalfCloseTimeout != 30*time.Second || c.BufferSize != 65536 ||
		c.BufferPoolMaxIdle != 3*c.MaxConnections || c.ReloadInterval != 5*time.Second {
		t.Fatalf("%+v", c)
	}
	if got := route(t, c, "x.a.com"); got != "x.b:443" { // action defaults to allow, port to 443
		t.Fatal(got)
	}
}

func TestConfigRouting(t *testing.T) {
	c := mustParse(t, "[global]\nport=1\n[[host]]\npattern=secret\\..*\naction=deny\n"+
		"[[host]]\npattern=(.*)\ntarget_host=$1\ntarget_port=8443\n")
	if route(t, c, "secret.x.com") != "DENY" || route(t, c, "public.x.com") != "public.x.com:8443" {
		t.Fatal("first match must win")
	}
	if route(t, c, "") != "ERROR" { // expands to an empty target host
		t.Fatal("empty target must be an error")
	}
	none := mustParse(t, "[global]\nport=1\n")
	if d := none.Route("a.com"); d.Allow || d.RuleLine != 0 {
		t.Fatalf("%+v", d)
	}
	re := mustParse(t, "[global]\nport=1\n[[host]]\npattern=(?:www\\.)?([a-z0-9-]+)\\.(?:example|sample)\\.(com|net)\ntarget_host=$1-$2.lan\n"+
		"[[host]]\npattern=node(\\d{1,3})\\.x\ntarget_host=node${1}-mgmt\n[[host]]\npattern=(x)?y\ntarget_host=got$1.lan\n")
	for sni, want := range map[string]string{
		"www.shop.example.com": "shop-com.lan:443", "API.Sample.NET": "api-net.lan:443",
		"a.b.example.com": "DENY", "node12.x": "node12-mgmt:443", "node1234.x": "DENY", "y": "got.lan:443",
	} {
		if got := route(t, re, strings.ToLower(sni)); got != want {
			t.Errorf("%q: got %s want %s", sni, got, want)
		}
	}
}

func TestNonePatternMatchesOnlyMissingSNI(t *testing.T) {
	c := mustParse(t, "[global]\nport=1\n[[host]]\npattern = NONE\ntarget_host = 10.0.0.99\ntarget_port = 8443\n"+
		"[[host]]\npattern = (.*)\\.ok\ntarget_host = $1.lan\n")
	for sni, want := range map[string]string{
		"": "10.0.0.99:8443", "a.ok": "a.lan:443",
		"none":  "DENY", // a host literally named "none" is not "no SNI"
		"other": "DENY",
	} {
		if got := route(t, c, sni); got != want {
			t.Errorf("%q: got %s want %s", sni, got, want)
		}
	}
	// Any letter case, quoted or not; and it can deny ahead of a catch-all allow.
	for _, form := range []string{"none", "None", `"NONE"`, "'none'"} {
		c := mustParse(t, "[global]\nport=1\n[[host]]\npattern="+form+"\naction=deny\n[[host]]\npattern=.*\ntarget_host=$0\n")
		if d := c.Route(""); d.Allow || d.RuleLine != 3 {
			t.Errorf("%s: %+v", form, d)
		}
		if got := route(t, c, "x.com"); got != "x.com:443" {
			t.Errorf("%s: %s", form, got)
		}
	}
	// The literal host name is still reachable with an explicit regex.
	lit := mustParse(t, "[global]\nport=1\n[[host]]\npattern=^none$\ntarget_host=n.lan\n")
	if route(t, lit, "none") != "n.lan:443" || route(t, lit, "") != "DENY" {
		t.Error("^none$ must match the host name, not a missing SNI")
	}
	// No groups to expand: $0 is empty (route error), $1 doesn't exist (load error).
	if got := route(t, mustParse(t, "[global]\nport=1\n[[host]]\npattern=NONE\ntarget_host=$0\n"), ""); got != "ERROR" {
		t.Error(got)
	}
	if _, err := ParseConfig("[global]\nport=1\n[[host]]\npattern=NONE\ntarget_host=$1.lan\n"); err == nil {
		t.Error("$1 with pattern NONE must be rejected")
	}
}

func TestConfigIgnoresRustOnlyKeys(t *testing.T) {
	c := mustParse(t, "[global]\nport=1\nio_model=events\nworker_threads=4\nshort_read_delay_us=50\n")
	if c.ShortReadDelay != 50*time.Microsecond {
		t.Fatal(c.ShortReadDelay)
	}
	if !reflect.DeepEqual(c.Ignored, []string{"io_model", "worker_threads"}) {
		t.Fatal(c.Ignored)
	}
}

func TestConfigErrors(t *testing.T) {
	for _, text := range []string{
		"[global]\nbind=1.2.3.4\n", // no port
		"[global]\nport=70000\n", "[global]\nport=0\n", "[global]\nport=abc\n", "port=1\n",
		"[global]\nport=1\n[other]\n", "[global]\nport=1\nfoo=bar\n", "[global]\nport=1\nnovalue\n", "[global\nport=1\n",
		"[global]\nport=1\nbuffer_size=100\n", "[global]\nport=1\nbuffer_size=99999999\n",
		"[global]\nport=1\nreload_interval=1\n", "[global]\nport=1\nreload_interval=4\n",
		"[global]\nport=1\n[[host]]\npattern=a\n", // allow without target
		"[global]\nport=1\n[[host]]\npattern=a\naction=nope\n",
		"[global]\nport=1\n[[host]]\npattern=\"abc\n", "[global]\nport=1\n[[host]]\npattern='abc\n",
		"[global]\nport=1\n[[host]]\npattern=\"a\" junk\n",
		"[global]\nport=1\n[[host]]\npattern=(\ntarget_host=x\n", // bad regex
		"[global]\nport=1\n[[host]]\npattern=a\ntarget_host=x\ntarget_port=0\n",
		"[global]\nport=1\n[[host]]\ntarget_host=x\n", // no pattern
		"[global]\nport=1\n[[host]]\npattern=a\ncolor=red\n",
		"[global]\nport=1\n[[host]]\npattern=.*\ntarget_host=$3\n", // no such group
	} {
		if _, err := ParseConfig(text); err == nil {
			t.Errorf("should fail: %q", text)
		}
	}
}

// Every samples/*.toml (and config.toml) must parse, and every
// "#> sni => target" line in it must route as documented.
func TestSamplesRouteAsDocumented(t *testing.T) {
	files, _ := filepath.Glob("samples/*.toml")
	files = append(files, "config.toml")
	checked := 0
	for _, path := range files {
		text, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := ParseConfig(string(text))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, line := range strings.Split(string(text), "\n") {
			if !strings.HasPrefix(line, "#>") {
				continue
			}
			sni, want, ok := strings.Cut(line[2:], "=>")
			if !ok {
				t.Fatalf("%s: bad expectation %q", path, line)
			}
			sni, want = strings.TrimSpace(sni), strings.TrimSpace(want)
			if sni == "<none>" {
				sni = ""
			}
			if got := route(t, cfg, strings.ToLower(sni)); got != want {
				t.Errorf("%s: routing %q: got %s want %s", path, sni, got, want)
			}
			checked++
		}
	}
	if checked < 40 {
		t.Fatalf("only %d expectations found", checked)
	}
}

// config.toml documents every default as a commented-out line; uncommenting
// them all must not change the parsed configuration.
func TestDocumentedDefaultsMatchCode(t *testing.T) {
	text, err := os.ReadFile("config.toml")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	uncommented := 0
	for _, l := range strings.Split(string(text), "\n") {
		if rest, ok := strings.CutPrefix(l, "# "); ok && strings.Contains(rest, " = ") && strings.Contains(rest, "(default:") {
			uncommented++
			l = rest
		}
		lines = append(lines, l)
	}
	if uncommented < 10 {
		t.Fatalf("only %d documented defaults found", uncommented)
	}
	asIs, explicit := mustParse(t, string(text)), mustParse(t, strings.Join(lines, "\n"))
	for _, c := range []*Config{asIs, explicit} {
		for i := range c.Rules {
			c.Rules[i].Pattern = nil // compiled regexps aren't comparable
		}
	}
	if !reflect.DeepEqual(asIs, explicit) {
		t.Fatalf("documented defaults differ from code:\n%+v\n%+v", asIs, explicit)
	}
}

// ---------------------------------------------------------------- cache

func fwd(host string) Decision { return Decision{Allow: true, Host: host, Port: 443, RuleLine: 1} }

func TestLRUEvictsExactlyLeastRecentlyUsed(t *testing.T) {
	c := newLRU[string](3)
	for _, k := range []string{"a", "b", "c"} {
		c.Put(k, k)
	}
	c.Get("a")      // recency now: a, c, b
	c.Put("d", "d") // evicts b
	if !c.Contains("a") || !c.Contains("c") || !c.Contains("d") || c.Contains("b") {
		t.Fatal("wrong eviction")
	}
	c.Put("e", "e") // evicts c
	c.Put("a", "a2")
	if v, _ := c.Get("a"); c.Contains("c") || c.Len() != 3 || v != "a2" {
		t.Fatal("wrong eviction or update")
	}
	one := newLRU[int](1)
	one.Put("a", 1)
	one.Put("b", 2)
	if one.Contains("a") || !one.Contains("b") {
		t.Fatal("capacity 1")
	}
}

func TestRouteCache(t *testing.T) {
	c := NewRouteCache(8, 8)
	calls := 0
	for i := 0; i < 3; i++ {
		_, hit := c.GetOrRoute("a.com", func() Decision { calls++; return fwd("x") })
		if hit != (i > 0) {
			t.Fatal("hit flag")
		}
	}
	c.GetOrRoute("bad.com", func() Decision { return Decision{RuleLine: 9} })
	c.GetOrRoute("err.com", func() Decision { return Decision{Err: "boom"} })
	if a, d := c.Len(); calls != 1 || a != 1 || d != 2 { // errors count as denials
		t.Fatal(calls, a, d)
	}
	if d, hit := c.GetOrRoute("bad.com", func() Decision { panic("cached") }); !hit || d.RuleLine != 9 {
		t.Fatal("denial not cached")
	}

	off := NewRouteCache(0, 0)
	calls = 0
	for i := 0; i < 3; i++ {
		off.GetOrRoute("a.com", func() Decision { calls++; return fwd("x") })
	}
	if calls != 3 {
		t.Fatal("capacity 0 must disable caching")
	}
}

func TestDenialFloodCannotEvictAllowedNames(t *testing.T) {
	c := NewRouteCache(4, 16)
	for _, n := range []string{"a.com", "b.com", "c.com"} {
		c.GetOrRoute(n, func() Decision { return fwd(n) })
	}
	for i := 0; i < 10000; i++ {
		c.GetOrRoute(fmt.Sprintf("scan%d.evil", i), func() Decision { return Decision{RuleLine: 2} })
	}
	if a, d := c.Len(); a != 3 || d != 16 {
		t.Fatal(a, d)
	}
	for _, n := range []string{"a.com", "b.com", "c.com"} {
		if _, hit := c.GetOrRoute(n, func() Decision { return fwd(n) }); !hit {
			t.Fatalf("%s evicted", n)
		}
	}
}

func TestCacheStaysWithinCapacityAndKeepsHotNames(t *testing.T) {
	c := NewRouteCache(100, 100)
	for i := 0; i < 10000; i++ {
		c.GetOrRoute(fmt.Sprintf("random%d.com", i), func() Decision { return fwd("x") })
		c.GetOrRoute("popular.com", func() Decision { return fwd("p") })
		if a, _ := c.Len(); a > 100 {
			t.Fatal("over capacity")
		}
	}
	if len(c.allow.slots) > 100 {
		t.Fatal("slots must be reused")
	}
	if _, hit := c.GetOrRoute("popular.com", func() Decision { return fwd("p") }); !hit {
		t.Fatal("hot name evicted")
	}
}

// ---------------------------------------------------------------- pool, formats

func TestBufferPool(t *testing.T) {
	p := NewBufferPool(4096, 2)
	a := p.Get()
	a[0] = 0xAA
	p.Put(a)
	if b := p.Get(); len(b) != 4096 || &b[0] != &a[0] {
		t.Fatal("buffer should be reused")
	}
	bufs := [][]byte{p.Get(), p.Get(), p.Get(), p.Get(), p.Get()}
	for _, b := range bufs {
		p.Put(b[:10]) // returned short: restored to full size
	}
	if p.Idle() != 2 { // extra returns are dropped
		t.Fatal(p.Idle())
	}
	if b := p.Get(); len(b) != 4096 {
		t.Fatal(len(b))
	}
	p.Put(make([]byte, 99)) // foreign buffer: ignored
	if p.Idle() != 1 {
		t.Fatal(p.Idle())
	}
	zero := NewBufferPool(512, 0) // pooling off: always allocate, always drop
	zero.Put(zero.Get())
	if zero.Idle() != 0 {
		t.Fatal("max idle 0")
	}
}

func TestFormats(t *testing.T) {
	for n, want := range map[int64]string{512: "512 B", 1536: "1.50 KiB", 5 << 30: "5.00 GiB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("%d: %s", n, got)
		}
	}
	for d, want := range map[time.Duration]string{42 * time.Millisecond: "42ms", 2500 * time.Millisecond: "2.50s", 3723 * time.Second: "1h02m03s", 90 * time.Second: "1m30s"} {
		if got := humanDuration(d); got != want {
			t.Errorf("%v: %s", d, got)
		}
	}
	var buf bytes.Buffer
	logMu.Lock()
	old := logOut
	logOut = &buf
	logMu.Unlock()
	logf("hello %d", 7)
	logMu.Lock()
	logOut = old
	logMu.Unlock()
	if s := buf.String(); len(s) != 24+1+8 || !strings.HasSuffix(s, "Z hello 7\n") {
		t.Fatalf("%q", s)
	}
}

// Every option the parser accepts must appear in the complete-reference sample,
// in the commented config.toml and in the README, so documentation can't drift.
func TestEveryOptionIsDocumented(t *testing.T) {
	src, err := os.ReadFile("config.go")
	if err != nil {
		t.Fatal(err)
	}
	notOptions := map[string]bool{"global": true, "logging": true, "console": true, "host": true, // sections
		"allow": true, "deny": true, "true": true, "false": true, "yes": true, "no": true, "on": true, "off": true} // values
	keys := map[string]bool{}
	for _, m := range regexp.MustCompile(`case ("[a-z_0-9]+"(?:, "[a-z_0-9]+")*):`).FindAllStringSubmatch(string(src), -1) {
		for _, k := range strings.Split(m[1], ", ") {
			if k = strings.Trim(k, `"`); !notOptions[k] {
				keys[k] = true
			}
		}
	}
	if len(keys) < 40 {
		t.Fatalf("only %d options found in config.go; did the parser change shape?", len(keys))
	}
	for _, doc := range []string{"samples/12-everything.toml", "config.toml", "README.md"} {
		text, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		for k := range keys {
			if !regexp.MustCompile(`(^|[^a-z_])` + k + `([^a-z_]|$)`).Match(text) {
				t.Errorf("%s does not mention the option %q", doc, k)
			}
		}
	}
}
