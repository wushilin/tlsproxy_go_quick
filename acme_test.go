package main

// End-to-end ACME test against Pebble, Let's Encrypt's official test CA, with
// its companion DNS server. Pebble validates TLS-ALPN-01 by connecting to our
// proxy exactly as Let's Encrypt would (only the port differs). Needs network
// access to install the two tools, so it only runs with TLSPROXY_PEBBLE=1:
//
//	TLSPROXY_PEBBLE=1 go test -run Pebble -v ./...

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const pebbleModule = "github.com/letsencrypt/pebble/v2"

func freePort(t *testing.T) int {
	l, port := listen(t)
	l.Close()
	return port
}

func runTool(t *testing.T, dir string, env []string, name string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off"), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

func startDaemon(t *testing.T, logName string, env []string, bin string, args ...string) {
	t.Helper()
	logFile, _ := os.Create(filepath.Join(t.TempDir(), logName))
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			data, _ := os.ReadFile(logFile.Name())
			t.Logf("---- %s ----\n%s", logName, data)
		}
	})
}

func waitForPort(t *testing.T, addr string) {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("%s never came up: %v", addr, err)
		}
	}
}

func TestPebbleIssuesOverTLSALPN01(t *testing.T) {
	if os.Getenv("TLSPROXY_PEBBLE") == "" {
		t.Skip("set TLSPROXY_PEBBLE=1 to run the ACME test against Pebble")
	}
	tools := t.TempDir()
	runTool(t, tools, []string{"GOBIN=" + tools}, "go", "install", pebbleModule+"/cmd/pebble@latest")
	runTool(t, tools, []string{"GOBIN=" + tools}, "go", "install", pebbleModule+"/cmd/pebble-challtestsrv@latest")
	var mod struct{ Dir string }
	if err := json.Unmarshal(runTool(t, tools, nil, "go", "mod", "download", "-json", pebbleModule+"@latest"), &mod); err != nil {
		t.Fatal(err)
	}
	pebbleCerts := filepath.Join(mod.Dir, "test", "certs")

	// The proxy under test, terminating TLS for two names with cert = auto.
	dnsPort, dnsMgmt, apiPort, apiMgmt := freePort(t), freePort(t), freePort(t), freePort(t)
	certPath := t.TempDir()
	p := startProxy(t, fmt.Sprintf("cert_path=%s\nacme_agree_tos=true\nacme_email=admin@acme.test\n"+
		"acme_directory=https://127.0.0.1:%d/dir\nacme_ca_file=%s\ndns_resolvers=127.0.0.1:%d\npublic_ip_address=127.0.0.1",
		certPath, apiPort, filepath.Join(pebbleCerts, "pebble.minica.pem"), dnsPort),
		fmt.Sprintf("[[host]]\npattern=(.*)\\.acme\\.test\ncert=auto\ncert_domains=www.acme.test, api.acme.test, elsewhere.acme.test\n"+
			"upstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=%d\n", echoBackend(t, "E")))
	_, proxyPort, _ := net.SplitHostPort(p.addr)

	// Fake public DNS: everything resolves to 127.0.0.1, except one name.
	startDaemon(t, "challtestsrv.log", nil, filepath.Join(tools, "pebble-challtestsrv"),
		"-defaultIPv4", "127.0.0.1", "-defaultIPv6", "", "-dnsserver", fmt.Sprintf("127.0.0.1:%d", dnsPort),
		"-management", fmt.Sprintf("127.0.0.1:%d", dnsMgmt), "-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", "")
	waitForPort(t, fmt.Sprintf("127.0.0.1:%d", dnsMgmt))
	body, _ := json.Marshal(map[string]any{"host": "elsewhere.acme.test", "addresses": []string{"198.51.100.9"}})
	if resp, err := http.Post(fmt.Sprintf("http://127.0.0.1:%d/add-a", dnsMgmt), "application/json", bytes.NewReader(body)); err != nil || resp.StatusCode != 200 {
		t.Fatalf("challtestsrv add-a: %v", err)
	}

	// The CA. tlsPort is where it connects for TLS-ALPN-01: our proxy.
	pebbleCfg := filepath.Join(tools, "pebble.json")
	os.WriteFile(pebbleCfg, []byte(fmt.Sprintf(`{"pebble": {"listenAddress": "127.0.0.1:%d", "managementListenAddress": "127.0.0.1:%d",
		"certificate": %q, "privateKey": %q, "httpPort": 5002, "tlsPort": %s, "ocspResponderURL": "",
		"externalAccountBindingRequired": false}}`, apiPort, apiMgmt,
		filepath.Join(pebbleCerts, "localhost", "cert.pem"), filepath.Join(pebbleCerts, "localhost", "key.pem"), proxyPort)), 0o644)
	startDaemon(t, "pebble.log", []string{"PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0"}, filepath.Join(tools, "pebble"),
		"-config", pebbleCfg, "-dnsserver", fmt.Sprintf("127.0.0.1:%d", dnsPort))
	waitForPort(t, fmt.Sprintf("127.0.0.1:%d", apiPort))

	// The worker's first pass ran before the CA was up and backed off; clear
	// that and poke it, as a config reload would.
	m := p.srv.certs
	m.mu.Lock()
	m.nextTry = map[string]time.Time{}
	m.mu.Unlock()
	m.wake <- struct{}{}

	issued := func(domain string) *tls.Certificate {
		m.mu.RLock()
		defer m.mu.RUnlock()
		return m.auto[domain]
	}
	for deadline := time.Now().Add(90 * time.Second); issued("www.acme.test") == nil || issued("api.acme.test") == nil; time.Sleep(200 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no certificates after 90s; proxy log:\n%s", testLog.String())
		}
	}

	// Clients now get the CA-issued certificate, and traffic flows.
	for _, name := range []string{"www.acme.test", "api.acme.test"} {
		tc, err := tlsDial(t, p, &tls.Config{InsecureSkipVerify: true, ServerName: name})
		if err != nil {
			t.Fatal(err)
		}
		chain := tc.ConnectionState().PeerCertificates
		if len(chain) < 2 || chain[0].DNSNames[0] != name || !strings.Contains(chain[0].Issuer.CommonName, "Pebble") {
			t.Fatalf("%s: got %d certs, leaf %v issued by %q", name, len(chain), chain[0].DNSNames, chain[0].Issuer.CommonName)
		}
		tc.Write([]byte("hi"))
		if got := string(readN(t, tc, 3)); got != "Ehi" {
			t.Fatal(got)
		}
		tc.Close()
		for _, f := range []string{"cert.pem", "key.pem"} { // persisted, private
			st, err := os.Stat(filepath.Join(certPath, name, f))
			if err != nil || st.Mode().Perm() != 0o600 {
				t.Fatalf("%s/%s: %v %v", name, f, err, st)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(certPath, "_account", "account.key")); err != nil {
		t.Fatal(err)
	}

	// The name that resolves elsewhere was never sent to the CA.
	log := testLog.String()
	if issued("elsewhere.acme.test") != nil || !strings.Contains(log, "elsewhere.acme.test resolves to 198.51.100.9") ||
		!strings.Contains(log, "answered the TLS-ALPN-01 challenge for www.acme.test") {
		t.Fatalf("DNS pre-check or challenge log missing:\n%s", log)
	}

	// Renewal: a second issuance reuses the account and replaces the certificate.
	before := issued("www.acme.test").Leaf.SerialNumber
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := m.issue(ctx, p.srv.runtime.Load().cfg, "www.acme.test"); err != nil {
		t.Fatalf("renewal: %v", err)
	}
	if after := issued("www.acme.test").Leaf.SerialNumber; after.Cmp(before) == 0 {
		t.Fatal("renewal did not replace the certificate")
	}

	// A restart finds the certificates on disk: no placeholder, no new order.
	fresh := NewCertManager()
	if err := fresh.Apply(p.srv.runtime.Load().cfg); err != nil || fresh.auto["api.acme.test"] == nil {
		t.Fatalf("certificates were not reloaded from %s: %v", certPath, err)
	}
	if jobs := fresh.pendingJobs(time.Now()); len(jobs) != 1 || jobs[0].domain != "elsewhere.acme.test" {
		t.Fatalf("after a restart only the unissued name should be pending: %+v", jobs)
	}
}
