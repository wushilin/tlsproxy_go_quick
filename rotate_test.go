package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func logLine(i int) string {
	return fmt.Sprintf("2026-09-19T04:47:08.212Z [#%05d] closed src=192.168.44.99:56076 sni=host.example.com reason=client closed\n", i)
}

func readGeneration(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, ".gz") {
		return string(raw)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return string(data)
}

func baseNames(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = filepath.Base(p)
	}
	return out
}

func TestLogRotatesNumbersCompressesAndPrunes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "stdout.log")
	os.WriteFile(path+".bak", []byte("unrelated"), 0o644) // never touched
	l, err := OpenFileLogger(path, LogConfig{MaxSize: 2000, MaxKeep: 5, CompressAfter: 2})
	if err != nil {
		t.Fatal(err)
	}
	var written strings.Builder
	for i := 0; i < 600; i++ {
		if err := l.WriteLine(logLine(i)); err != nil {
			t.Fatal(err)
		}
		written.WriteString(logLine(i))
		l.waitIdle() // deterministic: every rotation completes before the next line
	}
	gens := generations(path, 99)
	want := []string{"stdout.log.1", "stdout.log.2", "stdout.log.3.gz", "stdout.log.4.gz", "stdout.log.5.gz"}
	if got := baseNames(gens); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if !exists(path + ".bak") {
		t.Fatal("unrelated file was removed")
	}
	// Oldest generation first + live file = the tail of what was written.
	var tail strings.Builder
	for i := len(gens) - 1; i >= 0; i-- {
		g := readGeneration(t, gens[i])
		if len(g) < 2000 || len(g) > 2200 {
			t.Fatalf("%s: %d bytes", gens[i], len(g))
		}
		tail.WriteString(g)
	}
	live, _ := os.ReadFile(path)
	tail.Write(live)
	if !strings.HasSuffix(written.String(), tail.String()) || strings.Count(tail.String(), "\n") < 80 {
		t.Fatal("rotation lost, duplicated or reordered lines")
	}
}

func TestCompressGuardLetsTheFileOutgrow(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "g.log")
	l, _ := OpenFileLogger(path, LogConfig{MaxSize: 1000, MaxKeep: 4, CompressAfter: 0})
	for i := 0; i < 13; i++ {
		l.WriteLine(logLine(i)) // rotates once along the way
	}
	l.waitIdle()
	if n := len(generations(path, 9)); n != 1 {
		t.Fatal(n)
	}
	live, _ := os.ReadFile(path)
	before := strings.Count(string(live), "\n")

	l.compressing.Store(true) // hold the guard ourselves, as a slow compression would
	for i := 0; i < 100; i++ {
		l.WriteLine(logLine(i))
	}
	st, _ := os.Stat(path)
	if len(generations(path, 9)) != 1 || st.Size() < 10*1000 {
		t.Fatalf("rotated under the guard, or did not outgrow: gens=%d size=%d", len(generations(path, 9)), st.Size())
	}
	l.compressing.Store(false) // released: the very next line rotates, nothing lost
	l.WriteLine(logLine(999))
	l.waitIdle()
	gens := generations(path, 9)
	if len(gens) != 2 || strings.Count(readGeneration(t, gens[0]), "\n") != before+100 {
		t.Fatalf("%v", baseNames(gens))
	}
	if live, _ := os.ReadFile(path); string(live) != logLine(999) {
		t.Fatalf("live file: %q", live)
	}
}

func TestLogEdgeSettings(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "p.log")
	os.WriteFile(path, bytes.Repeat([]byte("x"), 900), 0o644)
	l, _ := OpenFileLogger(path, LogConfig{MaxSize: 1000, MaxKeep: 2, CompressAfter: 2}) // never compress
	l.WriteLine(strings.Repeat("y", 200))                                                // existing 900 bytes counted
	if len(generations(path, 9)) != 0 {
		t.Fatal("rotated too early")
	}
	for i := 0; i < 4; i++ {
		l.WriteLine(strings.Repeat("z", 1500))
		l.waitIdle()
	}
	if got := baseNames(generations(path, 9)); fmt.Sprint(got) != "[p.log.1 p.log.2]" {
		t.Fatal(got)
	}
	k := filepath.Join(dir, "k.log") // max_keep = 0: rotation just starts the file over
	l, _ = OpenFileLogger(k, LogConfig{MaxSize: 1000, MaxKeep: 0})
	for i := 0; i < 3; i++ {
		l.WriteLine(strings.Repeat("k", 1500))
		l.waitIdle()
	}
	if st, _ := os.Stat(k); len(generations(k, 9)) != 0 || st.Size() != 1500 {
		t.Fatal("max_keep=0")
	}
}

func TestLoggingSection(t *testing.T) {
	c := mustParse(t, "[global]\nport=1\n")
	if c.Log != defaultLogConfig() || c.Log.MaxSize != 15<<20 || c.Log.MaxKeep != 10 || c.Log.CompressAfter != 3 {
		t.Fatalf("%+v", c.Log)
	}
	c = mustParse(t, "[global]\nport=1\n[logging]\nstdout=stdout.log\nstderr = /var/log/tlsproxy.err\nmax_keep=10\n"+
		"compress_after=3 # stdout.log.4 is compressed\nmax_size=15MiB # rotated\n[[host]]\npattern=.*\naction=deny\n")
	if c.Log.Stdout != "stdout.log" || c.Log.Stderr != "/var/log/tlsproxy.err" || c.Log.MaxSize != 15<<20 || len(c.Rules) != 1 {
		t.Fatalf("%+v", c.Log)
	}
	for text, want := range map[string]int64{"1500": 1500, "64k": 64 << 10, "10M": 10 << 20, "10 MB": 10 << 20, "1GiB": 1 << 30} {
		if got := mustParse(t, "[global]\nport=1\n[logging]\nmax_size = "+text+"\n").Log.MaxSize; got != want {
			t.Errorf("%s: %d", text, got)
		}
	}
	for _, bad := range []string{"max_size=0", "max_size=ten", "max_size=5T", "compress_after=x", "max_keep=-1", "file=a.log"} {
		if _, err := ParseConfig("[global]\nport=1\n[logging]\n" + bad + "\n"); err == nil {
			t.Errorf("should fail: %s", bad)
		}
	}
}

// Runs the real binary: activity must go to the stdout file, problems to the
// stderr file, nothing to the terminal, and the files must rotate.
func TestBinaryLogsToRotatingFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bin := filepath.Join(dir, "tlsproxy")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	outLog, errLog, cfgPath := filepath.Join(dir, "stdout.log"), filepath.Join(dir, "stderr.log"), filepath.Join(dir, "config.toml")
	config := func(rules string) []byte {
		return []byte(fmt.Sprintf("[global]\nbind=127.0.0.1\nport=%d\nreload_interval=5\nstats_interval=0\n\n[logging]\nstdout=%s\nstderr=%s\n"+
			"max_keep=4\ncompress_after=1\nmax_size=3K\n\n%s", port, outLog, errLog, rules))
	}
	os.WriteFile(cfgPath, config("[[host]]\npattern=.*\naction=deny\n"), 0o644)
	var termOut, termErr bytes.Buffer
	cmd := exec.Command(bin, cfgPath)
	cmd.Stdout, cmd.Stderr = &termOut, &termErr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	addr := "127.0.0.1:" + strconv.Itoa(port)
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		} else if time.Now().After(deadline) {
			t.Fatal("proxy did not start")
		}
	}
	for i := 0; i < 150; i++ { // ~2 lines per denied connection: plenty of rotations at 3K
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		c.Write(clientHello(fmt.Sprintf("host%d.test", i)))
		io.Copy(io.Discard, c)
		c.Close()
	}
	// A broken config on reload is a problem: it belongs in the stderr file.
	os.WriteFile(cfgPath, config("[[host]]\npattern=(\n"), 0o644)
	for deadline := time.Now().Add(12 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if data, _ := os.ReadFile(errLog); strings.Contains(string(data), "is invalid") {
			break
		} else if time.Now().After(deadline) {
			t.Fatal("reload error never reached the stderr log")
		}
	}
	time.Sleep(300 * time.Millisecond) // let the last background compression finish
	cmd.Process.Kill()
	cmd.Wait()
	if termOut.Len()+termErr.Len() != 0 {
		t.Fatalf("leaked to the terminal:\n%s\n%s", termOut.String(), termErr.String())
	}
	gens := generations(outLog, 50)
	if got := fmt.Sprint(baseNames(gens)); got != "[stdout.log.1 stdout.log.2.gz stdout.log.3.gz stdout.log.4.gz]" {
		t.Fatal(got)
	}
	var text strings.Builder
	for i := len(gens) - 1; i >= 0; i-- {
		text.WriteString(readGeneration(t, gens[i]))
	}
	live, _ := os.ReadFile(outLog)
	text.Write(live)
	var ids []int // one continuous run of connection ids: no gap, no reordering
	for _, m := range regexp.MustCompile(`\[#(\d+)\] accepted from`).FindAllStringSubmatch(text.String(), -1) {
		n, _ := strconv.Atoi(m[1])
		ids = append(ids, n)
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] != ids[i-1]+1 {
			t.Fatalf("gap or reordering: %v", ids)
		}
	}
	errText, _ := os.ReadFile(errLog)
	if len(ids) < 30 || !strings.Contains(text.String(), "-> DENY") || strings.Contains(text.String(), "is invalid") ||
		strings.Contains(string(errText), "accepted from") {
		t.Fatalf("streams mixed up or too few lines (%d ids)", len(ids))
	}
	// The real gzip tool must accept our files, if installed.
	if gz, err := exec.LookPath("gzip"); err == nil {
		if out, err := exec.Command(gz, "-t", gens[len(gens)-1]).CombinedOutput(); err != nil {
			t.Fatalf("gzip -t: %v %s", err, out)
		}
	}
}
