package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// accessLine waits for the access record that contains want.
func accessLine(t *testing.T, want string) string {
	t.Helper()
	deadline := time.Now().Add(T)
	for time.Now().Before(deadline) {
		for _, l := range RecentLog(recentLogSize, want) {
			if strings.Contains(l, " access ") || strings.Contains(l, `"log":"access"`) {
				return l
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no access record with %q", want)
	return ""
}

// Every connection gets one record when it ends: passed through, denied, or
// not even TLS.
func TestAccessRecordsPerConnection(t *testing.T) {
	t.Parallel()
	port := echoBackend(t, "A")
	p := startProxy(t, "", fmt.Sprintf("[[host]]\nlistener=default\npattern=pass.access.test\ntarget_host=127.0.0.1\ntarget_port=%d\n"+
		"[[host]]\nlistener=default\npattern=ANY\naction=deny\n", port))
	roundtrip(t, p, "pass.access.test", "A")
	l := accessLine(t, "sni=pass.access.test ")
	for _, in := range []string{" kind=conn ", " listener=default ", " result=closed ", " mode=pass ", " rule=pass.access.test ",
		fmt.Sprintf(" dst=127.0.0.1:%d ", port), " up=", " down=", " dur_ms=", " reason="} {
		if !strings.Contains(l, in) {
			t.Errorf("passed through: %q lacks %q", l, in)
		}
	}
	expectDenied(t, p, clientHello("deny.access.test"))
	l = accessLine(t, "sni=deny.access.test ")
	if !strings.Contains(l, " result=denied ") || strings.Contains(l, " mode=") {
		t.Errorf("denied: %q", l)
	}
}

// Formats: logfmt quotes what would not read back as one value; json is one
// valid object per line.
func TestAccessRecordFormats(t *testing.T) {
	now := time.Date(2026, 11, 19, 8, 1, 2, 345e6, time.UTC)
	r := newAccessRecord("conn").num("id", 7).str("sni", "a.test").str("empty", "").str("reason", `client said "bye" a=b`)
	if got, want := r.line(now), `2026-11-19T08:01:02.345Z access kind=conn id=7 sni=a.test reason="client said \"bye\" a=b"`+"\n"; got != want {
		t.Errorf("logfmt:\n%q\nwant\n%q", got, want)
	}
	accessJSON.Store(true)
	defer accessJSON.Store(false)
	line := r.line(now)
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil || !strings.HasSuffix(line, "}\n") {
		t.Fatalf("json %q: %v", line, err)
	}
	if m["ts"] != "2026-11-19T08:01:02.345Z" || m["log"] != "access" || m["kind"] != "conn" || m["id"] != float64(7) || m["reason"] != `client said "bye" a=b` {
		t.Errorf("json: %v", m)
	}
	if _, ok := m["empty"]; ok {
		t.Error("json has an empty field")
	}
	for in, want := range map[string]string{" (listing)": "listing", " via serve 9 (index.html)": "via serve 9 (index.html)", "": ""} {
		if got := accessNote(in); got != want {
			t.Errorf("accessNote(%q) = %q, want %q", in, got, want)
		}
	}
	for v, want := range map[string]string{"": `""`, "a b": `"a b"`, "x\ny": `"x\ny"`, "plain/1.0": "plain/1.0", "é": `"é"`} {
		if got := logfmtValue(v); got != want {
			t.Errorf("logfmtValue(%q) = %s, want %s", v, got, want)
		}
	}
}

// access: a file of its own, off, and verbose: false. Not parallel: the
// destinations are the process's.
func TestAccessLogDestinations(t *testing.T) {
	defer ConfigureLogging(defaultLogConfig())
	file := filepath.Join(t.TempDir(), "access.log")
	cfg := defaultLogConfig()
	cfg.Access, cfg.AccessTag, cfg.Verbose = file, "node-1", false
	if err := ConfigureLogging(cfg); err != nil {
		t.Fatal(err)
	}
	accessConn(&flowView{ID: 99, Listener: "x", Src: "192.0.2.9:1", SNI: "file.access.test", Routed: true, Result: flowClosed,
		Started: time.Now().UnixMilli(), Ended: time.Now().UnixMilli(), flowHow: flowHow{TLS: "passthrough"}})
	vlogf("verbose-line-should-not-appear")
	logf("activity-line-still-appears")
	FlushLogs()
	data, _ := os.ReadFile(file)
	if s := string(data); !strings.Contains(s, " access kind=conn node=node-1 id=99 ") || !strings.Contains(s, " mode=pass ") || strings.Contains(s, "activity-line") {
		t.Errorf("access file: %q", s)
	}
	if len(RecentLog(10, "verbose-line-should-not-appear")) != 0 || len(RecentLog(10, "activity-line-still-appears")) != 1 {
		t.Error("verbose: false did not drop only the per-connection lines")
	}

	cfg.Access = "off"
	if err := ConfigureLogging(cfg); err != nil {
		t.Fatal(err)
	}
	accessConn(&flowView{ID: 100, SNI: "off.access.test", Routed: true})
	if len(RecentLog(10, "off.access.test")) != 0 {
		t.Error("access: off still records")
	}

	for in, want := range map[string]string{"stdout": "", "STDERR": "stderr", "none": "off", "/x/a.log": "/x/a.log"} {
		c := mustParse(t, "[[listener]]\nname=default\nport=1\n[logging]\naccess = "+in+"\n")
		if c.Log.Access != want {
			t.Errorf("access=%s: %q, want %q", in, c.Log.Access, want)
		}
	}
	if c := mustParse(t, "[[listener]]\nname=default\nport=1\n"); !c.Log.Verbose || c.Log.AccessFormat != "logfmt" || c.Log.Access != "" {
		t.Errorf("defaults: %+v", c.Log)
	}
}
