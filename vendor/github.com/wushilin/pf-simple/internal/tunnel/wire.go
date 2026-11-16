package tunnel

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// The relay's endpoints and headers. Everything secret travels in headers,
// which reverse proxies do not log by default; URLs they do.
const (
	Path         = "/pf/api/tunnel"   // + "/serve", "/connect", "/accept", "/check"
	HeaderWord   = "X-PF-Tunnel-Word" // the tunnel's secret word
	HeaderServe  = "X-PF-Serve-Token" // permission to register; only "serve" sends it
	HeaderConn   = "X-PF-Tunnel-Conn"
	HeaderName   = "X-PF-Tunnel-Name" // what the tunnel is called in the console; URL-escaped
	HeaderTarget = "X-PF-Tunnel-Target"
	HeaderError  = "X-PF-Tunnel-Error"
	// A serving side may ask for a client token on top of the word. It
	// registers the token's SHA-256, and the connecting side sends the token.
	HeaderClientHash  = "X-PF-Client-Token-SHA256"
	HeaderClientToken = "X-PF-Client-Token"
	// HeaderOp says what a QUIC discovery is for: "serve" or "connect"
	// (protocol 3; only that endpoint has it).
	HeaderOp = "X-PF-Tunnel-Op"

	MinSecret = 32
	MaxSecret = 128
	// A client token is typed by people, like a password.
	MinClientToken = 8

	// The serving side pings its control channel; either end gives up on it
	// after ControlSilence.
	ControlPing    = 20 * time.Second
	ControlSilence = 60 * time.Second
)

// A word names one tunnel and is typed on both sides, so it is short and
// easy to read out: three groups of four letters or digits, in any case.
// A generated word leaves out the characters that are mistaken for one
// another (0 and o, 1, i and l); it carries 59 bits, and can only be guessed
// against the live server, one request at a time. A typed word may use any
// letter or digit.
const (
	wordAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	wordExample  = "k3f9-x2mq-7hpa"
)

var wordPattern = regexp.MustCompile(`^[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$`)

// NormalizeWord checks a word and returns it in the lower case both ends
// use from then on.
func NormalizeWord(word string) (string, error) {
	word = strings.ToLower(strings.TrimSpace(word))
	if !wordPattern.MatchString(word) {
		return "", fmt.Errorf("the word must be three groups of four letters or digits, like %s (case does not matter); leave it out and 'pf-client serve' makes a random one", wordExample)
	}
	return word, nil
}

// NewWord returns a random word that is easy to read out.
func NewWord() (string, error) {
	out := make([]byte, 0, 14)
	var b [1]byte
	for len(out) < 14 {
		if len(out) == 4 || len(out) == 9 {
			out = append(out, '-')
			continue
		}
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		if n := len(wordAlphabet); int(b[0]) < 256/n*n { // no modulo bias
			out = append(out, wordAlphabet[int(b[0])%n])
		}
	}
	return string(out), nil
}

// CheckSecret applies the rules for serve tokens: long enough to be a
// secret, and plain enough to travel in a header. what names the secret in
// the error.
func CheckSecret(what, secret string) error {
	if len(secret) < MinSecret {
		return fmt.Errorf("the %s must be at least %d characters long (got %d)", what, MinSecret, len(secret))
	}
	if len(secret) > MaxSecret {
		return fmt.Errorf("the %s must be at most %d characters long", what, MaxSecret)
	}
	for _, c := range secret {
		if c <= ' ' || c > '~' {
			return fmt.Errorf("the %s may only use printable ASCII characters, without spaces", what)
		}
	}
	return nil
}

// CheckClientToken applies the rules for client tokens: 8 to 128 printable
// ASCII characters, without spaces.
func CheckClientToken(token string) error {
	if len(token) < MinClientToken {
		return fmt.Errorf("the client token must be at least %d characters long (got %d)", MinClientToken, len(token))
	}
	if len(token) > MaxSecret {
		return fmt.Errorf("the client token must be at most %d characters long", MaxSecret)
	}
	for _, c := range token {
		if c <= ' ' || c > '~' {
			return errors.New("the client token may only use printable ASCII characters, without spaces")
		}
	}
	return nil
}

// ControlMessage is what the relay sends down a serving side's control
// channel: open a connection to your target and bring it to /accept.
type ControlMessage struct {
	Open string `json:"open"`
}

// The text frames of protocol 2 on an accept leg that was offered reuse
// (docs/PROTOCOL.md §12).
const (
	MsgIdle  = "idle"  // hub: a clean finish; client: keep this leg
	MsgBind  = "bind"  // hub: "bind <id>", the next connection on this idle leg
	MsgBound = "bound" // client: "bound <id>", taken
)

// StdioTarget is the target a serving side names when it offers its own
// stdin/stdout instead of a TCP port.
const StdioTarget = "stdio"

// Fingerprint is the certificate's SHA-256, as AA:BB:...
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	text := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(text); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(text[i : i+2])
	}
	return b.String()
}

// HashClientToken is what a serving side registers for its client token:
// the SHA-256 of the token, in hex.
func HashClientToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
