package main

// End-to-end ACME tests against Pebble, Let's Encrypt's official test CA,
// run in this process from its vendored packages: no download, no separate
// program, no network beyond localhost, so they run in every go test on any
// host. Pebble validates TLS-ALPN-01 by connecting to our proxy exactly as
// Let's Encrypt would (only the port differs); its DNS is a fake server here.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pebbleca "github.com/letsencrypt/pebble/v2/ca"
	pebbledb "github.com/letsencrypt/pebble/v2/db"
	pebbleva "github.com/letsencrypt/pebble/v2/va"
	pebblewfe "github.com/letsencrypt/pebble/v2/wfe"
)

// pebble is Pebble running in this process: its ACME API on an HTTPS
// server of its own, its DNS a fake server.
type pebble struct {
	api     *httptest.Server
	handler atomic.Pointer[http.Handler] // set once the proxy's port is known
	serve   sync.Mutex                   // one ACME request at a time: Pebble has races of its own
	mgmt    http.Handler
	caFile  string // trust for the API's own HTTPS (acme_ca_file)
	dns     string
	log     *bytes.Buffer
	logMu   sync.Mutex
}

// newPebble starts the API's HTTPS server and the DNS (every name resolves
// to 127.0.0.1, but those in other). Pebble itself starts with start, once
// the proxy it validates against is listening.
func newPebble(t *testing.T, other map[string]string) *pebble {
	t.Helper()
	pb := &pebble{dns: fakeDNSWith(t, "127.0.0.1", other), log: &bytes.Buffer{}}
	pb.api = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := pb.handler.Load(); h != nil {
			// Pebble is the test's CA, not what is tested: serve it one request
			// at a time. Built with -race in this process, its own unguarded
			// shared state (two new-account requests at once) would otherwise
			// fail the run.
			pb.serve.Lock()
			defer pb.serve.Unlock()
			(*h).ServeHTTP(w, r)
			return
		}
		http.Error(w, "not started yet", http.StatusServiceUnavailable)
	}))
	pb.api.StartTLS()
	t.Cleanup(pb.api.Close)
	pb.caFile = filepath.Join(t.TempDir(), "pebble-api.pem")
	os.WriteFile(pb.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pb.api.Certificate().Raw}), 0o644)
	t.Cleanup(func() {
		if t.Failed() {
			pb.logMu.Lock()
			t.Logf("---- pebble ----\n%s", pb.log)
			pb.logMu.Unlock()
		}
	})
	return pb
}

// global is what a proxy's [global] needs to get certificates from it.
func (pb *pebble) global(certPath string) string {
	return fmt.Sprintf("cert_path=%s\nacme_agree_tos=true\nacme_email=admin@acme.test\n"+
		"acme_directory=%s/dir\nacme_ca_file=%s\ndns_resolvers=%s\npublic_ip_address=127.0.0.1", certPath, pb.api.URL, pb.caFile, pb.dns)
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// start runs Pebble, validating TLS-ALPN-01 on the proxy's proxyPort.
func (pb *pebble) start(t *testing.T, proxyPort string) {
	t.Helper()
	port, _ := strconv.Atoi(proxyPort)
	logger := log.New(lockedWriter{&pb.logMu, pb.log}, "pebble ", log.LstdFlags)
	db := pebbledb.NewMemoryStore()
	ca := pebbleca.New(logger, db, "", "ecdsa", 0, 1, map[string]pebbleca.Profile{"default": {Description: "default"}})
	va := pebbleva.New(logger, 5002, port, false, pb.dns, db)
	wfe := pebblewfe.New(logger, db, va, ca, []string{"pebble.letsencrypt.org"}, false, false, 3, 5)
	h := wfe.Handler()
	pb.mgmt = wfe.ManagementHandler()
	pb.handler.Store(&h)
}

// roots is the root Pebble issues under (a new one each run).
func (pb *pebble) roots(t *testing.T) *x509.CertPool {
	t.Helper()
	rec := httptest.NewRecorder()
	pb.mgmt.ServeHTTP(rec, httptest.NewRequest("GET", "/roots/0", nil))
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rec.Body.Bytes()) {
		t.Fatalf("no root from Pebble: %s", rec.Body)
	}
	return pool
}

func freePort(t *testing.T) int {
	l, port := listen(t)
	l.Close()
	return port
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
	t.Parallel()
	pb := newPebble(t, map[string]string{"elsewhere.acme.test": "198.51.100.9"}) // one name points elsewhere

	// The proxy under test, terminating TLS for two names with cert = auto.
	certPath := t.TempDir()
	p := startProxy(t, pb.global(certPath),
		fmt.Sprintf("[[host]]\nlistener=default\npattern=*.acme\\.test\ncert=auto\ncert_domains=www.acme.test, api.acme.test, elsewhere.acme.test\n"+
			"upstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=%d\n", echoBackend(t, "E")))
	_, proxyPort, _ := net.SplitHostPort(p.addr)

	// The CA: validating through the proxy.
	m := p.srv.certs
	pb.start(t, proxyPort)
	retryCertificatesNow(m)

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
			// Mode 0600 is Unix's notion of private; Windows has no mode bits
			// (its ACLs come from the directory), so there only presence counts.
			if err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o600) {
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

// retryCertificatesNow clears the worker's backoff (its first pass ran
// before the CA was up) and pokes it, as a config reload would.
func retryCertificatesNow(m *CertManager) {
	m.lock()
	m.nextTry = map[string]time.Time{}
	m.unlock()
	m.wake <- struct{}{}
}
