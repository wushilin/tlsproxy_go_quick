package main

import (
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseRate(t *testing.T) {
	for in, want := range map[string]float64{
		"100Mbit": 12.5e6, "100 Mbps": 12.5e6, "2.5Gbps": 312.5e6, "8bit": 1, "8b/s": 1,
		"800KB/s": 800e3, "50MB": 50e6, "1GB/s": 1e9, "512B/s": 512, "512B": 512,
		"14KiB/s": 14 << 10, "64MiB/s": 64 << 20, "1GiB": 1 << 30, "1gib/s": 1 << 30,
		"10Mb": 1.25e6, "10mbit": 1.25e6, "1Kb": 125,
	} {
		if got, err := parseRate(in); err != nil || got != want {
			t.Errorf("parseRate(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "100", "Mbit", "0MB", "-1MB", "1 furlong", "1bit", "1e3MB", "1.2.3MB"} {
		if _, err := parseRate(bad); err == nil {
			t.Errorf("parseRate(%q) accepted", bad)
		}
	}
}

func TestSpeedSettings(t *testing.T) {
	c := mustParse(t, "[[listener]]\nname=default\nport=1\n[[host]]\nlistener = default\npattern=a.test\ntarget_host=x\ntarget_port = 443\nmax_aggregated_speed=1Gbit\nmax_single_connection_speed = \"15MiB/s\"\n")
	if r := c.Rules[0]; r.MaxAggregatedSpeed != 125e6 || r.MaxSingleConnectionSpeed != 15<<20 {
		t.Fatal(r.MaxAggregatedSpeed, r.MaxSingleConnectionSpeed)
	}
	for text, want := range map[string]string{
		"pattern=a.test\naction=deny\nmax_aggregated_speed=1MB":                            "max_aggregated_speed makes no sense on a deny rule",
		"pattern=a.test\ntarget_host=x\ntarget_port=443\nmax_single_connection_speed=fast": "max_single_connection_speed: invalid rate",
	} {
		_, err := ParseConfig("[[listener]]\nname=default\nport=1\n[[host]]\nlistener=default\n" + text + "\n")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", text, err, want)
		}
	}
}

// A reload keeps a rule's shared budget when its pattern and rate are
// unchanged, and starts a new one when the rate changes.
func TestAggregateBudgetSurvivesReload(t *testing.T) {
	text := "[[listener]]\nname=default\nport=1\n[[host]]\nlistener=default\npattern=a.test\ntarget_host=x\ntarget_port=443\nmax_aggregated_speed=%s\n"
	parse := func(rate string) *Config { return mustParse(t, strings.Replace(text, "%s", rate, 1)) }
	rt1 := newRuntime(parse("1MB"), nil)
	rt2 := newRuntime(parse("1MB"), rt1)
	rt3 := newRuntime(parse("2MB"), rt2)
	l1, l2, l3 := rt1.limits[&rt1.cfg.Rules[0]], rt2.limits[&rt2.cfg.Rules[0]], rt3.limits[&rt3.cfg.Rules[0]]
	if l1 == nil || l1 != l2 || l3 == l2 || l3.dir[0].rate != 2e6 {
		t.Fatalf("%p %p %p", l1, l2, l3)
	}
}

// sink is a backend that reads everything and reports when the client is done.
func sink(t *testing.T) int {
	return backend(t, func(c *net.TCPConn) { io.Copy(io.Discard, c) })
}

// upload sends n bytes after a ClientHello and waits for the proxy to finish.
func upload(t *testing.T, p *proxyUnderTest, sni string, n int) {
	c := dial(t, p)
	c.SetDeadline(time.Now().Add(30 * time.Second))
	c.Write(clientHello(sni))
	if _, err := c.Write(make([]byte, n)); err != nil {
		t.Error(err)
	}
	c.CloseWrite()
	io.Copy(io.Discard, c)
}

// The limits hold on both data paths. Only the lower bound is tight: the
// burst is one chunk, so n bytes can't take less than (n - chunk) / rate.
func TestSpeedLimits(t *testing.T) {
	t.Parallel()
	for _, splice := range []string{"splice=true", "splice=false"} {
		t.Run(splice, func(t *testing.T) {
			t.Parallel()
			const n = 3 << 19 // 1.5 MiB
			port := strconv.Itoa(sink(t))
			// One connection at 1 MiB/s: 1.5 MiB.
			single := startProxy(t, splice, "[[host]]\nlistener=default\npattern=ANY\ntarget_host=127.0.0.1\ntarget_port="+port+"\nmax_single_connection_speed=1MiB/s\n")
			t0 := time.Now()
			upload(t, single, "one.test", n)
			between(t, t0, 1300*time.Millisecond, 4*time.Second)

			// Two connections sharing the rule's 1 MiB/s: 3 MiB together.
			agg := startProxy(t, splice, "[[host]]\nlistener=default\npattern=*.test\ntarget_host=127.0.0.1\ntarget_port="+port+"\nmax_aggregated_speed=1MiB/s\n")
			t0 = time.Now()
			var wg sync.WaitGroup
			for _, sni := range []string{"a.test", "b.test"} {
				wg.Add(1)
				go func() { defer wg.Done(); upload(t, agg, sni, n) }()
			}
			wg.Wait()
			between(t, t0, 2800*time.Millisecond, 6*time.Second)
		})
	}
}

// buffer_size outside 4 KiB..128 KiB is clamped, and the config says so.
func TestBufferSizeIsClampedWithWarning(t *testing.T) {
	for in, want := range map[string]int{"512": minBufferSize, "1048576": maxBufferSize, "65536": 65536} {
		c := mustParse(t, "[[listener]]\nname=default\nport=1\n[global]\nbuffer_size="+in+"\n")
		warned := len(c.Warnings) == 1 && strings.Contains(c.Warnings[0], "line 5: buffer_size = "+in+" is outside 4096..131072; using "+strconv.Itoa(want))
		if c.BufferSize != want || warned != (in != "65536") {
			t.Errorf("buffer_size=%s: got %d, warnings %q", in, c.BufferSize, c.Warnings)
		}
	}
}
