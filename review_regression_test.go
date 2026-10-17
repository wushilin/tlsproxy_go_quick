package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPasswordUpdateWaitsForLogin(t *testing.T) {
	oldHash, err := hashPassword("old")
	if err != nil {
		t.Fatal(err)
	}
	newHash, err := hashPassword("new")
	if err != nil {
		t.Fatal(err)
	}
	c := &Console{hash: oldHash, sessions: map[string]*session{}}
	// Simulate an admitted login still verifying the old hash.
	c.verifyMu.Lock()
	done := make(chan struct{})
	go func() { c.update(&ConsoleConfig{PasswordHash: newHash}); close(done) }()
	select {
	case <-done:
		c.verifyMu.Unlock()
		t.Fatal("password update passed an ongoing login")
	case <-time.After(20 * time.Millisecond):
	}
	c.mu.Lock()
	c.sessions["old-session"] = &session{expires: time.Now().Add(time.Hour)}
	c.mu.Unlock()
	c.verifyMu.Unlock()
	select {
	case <-done:
	case <-time.After(T):
		t.Fatal("password update stalled")
	}
	if len(c.sessions) != 0 || c.hash != newHash {
		t.Fatal("old login survived password update")
	}
	req := httptest.NewRequest("GET", "/api/session", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "old-session"})
	w := httptest.NewRecorder()
	// A revocation after the middleware's check must return 401, not panic.
	c.sessionInfo(w, req)
	if w.Code != 401 {
		t.Fatalf("revoked session: %d", w.Code)
	}
}

func TestConsoleSecureCookies(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		configured, directTLS, want bool
	}{
		{"local HTTP", false, false, false},
		{"published HTTPS", true, false, true},
		{"direct TLS", false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustParse(t, "[global]\nport=1\n[console]\nport=9443\npassword=x\nsecure_cookie="+strconv.FormatBool(tc.configured)+"\n")
			hash, err := hashPassword("x")
			if err != nil {
				t.Fatal(err)
			}
			cfg.Console.PasswordHash = hash
			c := &Console{sessions: map[string]*session{}}
			c.update(cfg.Console)
			req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"password":"x"}`))
			if tc.directTLS {
				req.TLS = &tls.ConnectionState{}
			}
			w := httptest.NewRecorder()
			c.login(w, req)
			cookies := w.Result().Cookies()
			if w.Code != 200 || len(cookies) != 1 || cookies[0].Secure != tc.want || !cookies[0].HttpOnly {
				t.Fatalf("status=%d cookies=%v", w.Code, cookies)
			}
			cfg.Console.SecureCookie = !tc.configured
			c.update(cfg.Console)
			if len(c.sessions) != 0 {
				t.Fatal("cookie policy change did not revoke old sessions")
			}
		})
	}
	if _, err := ParseConfig("[global]\nport=1\n[console]\nport=9443\npassword=x\nsecure_cookie=invalid\n"); err == nil {
		t.Fatal("invalid secure_cookie accepted")
	}
}

func TestDirectoryCertificateChainAndKeyRefresh(t *testing.T) {
	ca := newTestCA(t)
	dir := ca.certDir(t, "refresh.test")
	m := NewCertManager()
	initial, err := loadDirCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	m.files[dir] = initial
	certPEM, err := os.ReadFile(filepath.Join(dir, "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	m.refreshFileCerts()
	withChain := m.files[dir]
	if len(withChain.cert.Certificate) != len(initial.cert.Certificate)+1 {
		t.Fatal("ca.pem addition ignored")
	}
	if err := os.Remove(filepath.Join(dir, "ca.pem")); err != nil {
		t.Fatal(err)
	}
	m.refreshFileCerts()
	if len(m.files[dir].cert.Certificate) != len(initial.cert.Certificate) {
		t.Fatal("ca.pem removal ignored")
	}
	previous := m.files[dir]
	key, err := os.ReadFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), []byte("broken key"), 0600); err != nil {
		t.Fatal(err)
	}
	m.refreshFileCerts()
	if m.files[dir] != previous {
		t.Fatal("broken key replaced working certificate")
	}
	// Change only the key's encoding, retaining the matching private key.
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), append(key, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	m.refreshFileCerts()
	if m.files[dir] == previous {
		t.Fatal("key-only change ignored")
	}
}

type partialWriteConn struct {
	net.Conn
	input   *bytes.Reader
	written int
	err     error
}

func (c *partialWriteConn) Read(b []byte) (int, error)  { return c.input.Read(b) }
func (c *partialWriteConn) Write(b []byte) (int, error) { return min(c.written, len(b)), c.err }
func (c *partialWriteConn) CloseWrite() error           { return nil }

func TestRelayCountsPartialWrites(t *testing.T) {
	for _, err := range []error{io.ErrClosedPipe, nil} {
		c := &ConnState{host: &HostStats{}}
		c.SToC.Store(dirHalfClosed)
		st := NewStats()
		pool := NewBufferPool(1024, 2)
		defer pool.Stop()
		r := &relay{c: c, stats: st, cfg: &Config{}, pool: pool,
			client: &partialWriteConn{input: bytes.NewReader([]byte("abcdef"))},
			server: &partialWriteConn{written: 3, err: err}}
		r.pump(cToS)
		if c.BytesUp.Load() != 3 || st.BytesUp.Load() != 3 || c.host.BytesUp.Load() != 3 {
			t.Fatal("partial write bytes missing")
		}
		if c.CToS.Load() != dirHalfClosed {
			t.Fatal("partial write did not end direction")
		}
	}
}

func TestPasswordRewriteRejectsStaleSnapshot(t *testing.T) {
	oldText := "[global]\nport=443\n[console]\nport=9443\npassword=old-password\n"
	for name, newText := range map[string]string{
		"new password":    strings.ReplaceAll(oldText, "old-password", "new-password"),
		"unrelated edit":  oldText + "# newer edit\n",
		"console removed": "[global]\nport=443\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			cfg := mustParse(t, oldText)
			if err := os.WriteFile(path, []byte(newText), 0600); err != nil {
				t.Fatal(err)
			}
			if (&Server{}).securePassword(path, cfg) {
				t.Fatal("stale snapshot rewrote a newer file")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != newText {
				t.Fatal("newer file was overwritten")
			}
			// A fresh parse can still hash the current password normally.
			fresh := mustParse(t, newText)
			if fresh.Console != nil {
				password := fresh.Console.Password
				if !(&Server{}).securePassword(path, fresh) {
					t.Fatal("current snapshot could not rewrite password")
				}
				data, err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				saved := mustParse(t, string(data))
				if !checkPassword(saved.Console.PasswordHash, password) || fresh.sourceHash != saved.sourceHash {
					t.Fatal("password or tracked snapshot differs from the saved file")
				}
			}
		})
	}
}

func TestCertificateReloadCancelsIssuance(t *testing.T) {
	cfg := mustParse(t, fmt.Sprintf("[global]\nport=443\ncert_path=%s\nacme_agree_tos=true\n[[host]]\npattern=removed.example.com\ncert=auto\ntarget_host=127.0.0.1\n", t.TempDir()))
	m := NewCertManager()
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	started := make(chan context.Context, 1)
	m.issueFunc = func(ctx context.Context, _ *Config, _ string) error {
		started <- ctx
		<-ctx.Done()
		return ctx.Err()
	}
	job := certJob{domain: "removed.example.com", urgent: true}
	if !m.startJob(cfg, job) {
		t.Fatal("job did not start")
	}
	var ctx context.Context
	select {
	case ctx = <-started:
	case <-time.After(T):
		t.Fatal("issuer did not start")
	}
	if m.startJob(cfg, job) {
		t.Fatal("duplicate job started")
	}
	// A rejected config must leave the current generation alive.
	bad := mustParse(t, "[global]\nport=443\n[[host]]\npattern=ANY\ncert=/nonexistent/review-cert\ntarget_host=127.0.0.1\n")
	if err := m.Apply(bad); err == nil {
		t.Fatal("bad config accepted")
	}
	if ctx.Err() != nil {
		t.Fatal("rejected config canceled a current job")
	}
	newCfg := mustParse(t, "[global]\nport=443\n")
	if err := m.Apply(newCfg); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(T):
		t.Fatal("obsolete issuance was not canceled")
	}
	for deadline := time.Now().Add(T); ; {
		m.mu.RLock()
		active := len(m.inFlight)
		failures := len(m.nextTry) + len(m.lastError)
		m.mu.RUnlock()
		if active == 0 {
			if failures != 0 {
				t.Fatal("canceled job wrote obsolete failure state")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("canceled job did not release its slot")
		}
		time.Sleep(time.Millisecond)
	}
	if m.startJob(cfg, job) {
		t.Fatal("job started for obsolete config")
	}
}

func TestCertificateInstallRejectsObsoleteResult(t *testing.T) {
	cfg := mustParse(t, fmt.Sprintf("[global]\nport=443\ncert_path=%s\nacme_agree_tos=true\n[[host]]\npattern=commit.example.com\ncert=auto\ntarget_host=127.0.0.1\n", t.TempDir()))
	m := NewCertManager()
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	oldCtx := m.cfgCtx
	certPEM, keyPEM := newTestCA(t).issue(t, time.Hour, "commit.example.com")
	// Even applying the same Config pointer creates a new generation.
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if err := m.installCertificate(oldCtx, cfg, "commit.example.com", certPEM, keyPEM); !errors.Is(err, context.Canceled) {
		t.Fatalf("obsolete install: %v", err)
	}
	if _, err := os.Stat(autoDir(cfg, "commit.example.com")); !os.IsNotExist(err) {
		t.Fatalf("obsolete result touched disk: %v", err)
	}
	if m.auto["commit.example.com"] != nil {
		t.Fatal("obsolete result installed in memory")
	}
	if err := m.installCertificate(m.cfgCtx, cfg, "commit.example.com", certPEM, keyPEM); err != nil {
		t.Fatalf("current install: %v", err)
	}
	if m.auto["commit.example.com"] == nil {
		t.Fatal("current certificate was not installed")
	}
	// Pointer changes must also reject a result even if its caller supplied
	// an independent context that the reload could not cancel.
	if err := m.Apply(mustParse(t, "[global]\nport=443\n")); err != nil {
		t.Fatal(err)
	}
	if err := m.installCertificate(context.Background(), cfg, "other.example.com", certPEM, keyPEM); !errors.Is(err, context.Canceled) {
		t.Fatalf("obsolete config install: %v", err)
	}
}

func TestReloadUsesParsedSnapshotAtStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	oldText := "[global]\nport=1\nreload_interval=0\nstats_interval=0\n[[host]]\npattern=ANY\naction=deny\n"
	newText := strings.ReplaceAll(oldText, "stats_interval=0", "stats_interval=17")
	if err := os.WriteFile(path, []byte(newText), 0600); err != nil {
		t.Fatal(err)
	}
	p := startProxyText(t, oldText, path)
	// Trigger immediately, including before the watcher gets scheduled.
	p.srv.reloadNow <- struct{}{}
	for deadline := time.Now().Add(T); ; {
		if p.srv.runtime.Load().cfg.StatsInterval == 17*time.Second {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("file changed before watcher startup was skipped")
		}
		time.Sleep(time.Millisecond)
	}
}
