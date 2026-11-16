// Package pfrelay is the Go SDK for the pf-simple relay hub: serve a tunnel
// or connect through one from your own program. The protocol is described
// in docs/PROTOCOL.md.
//
// The package is licensed under the Apache License 2.0; see the LICENSE
// file in this directory.
package pfrelay

import (
	"errors"

	"github.com/wushilin/pf-simple/internal/tunnel"
)

// DefaultAgent is what a Client calls itself when Agent is empty.
const DefaultAgent = "pfrelay-go"

// ErrAccessDenied is the server refusing a token or word (403).
var ErrAccessDenied = errors.New("access denied")

type (
	ServerInfo  = tunnel.ServerInfo
	ProtoError  = tunnel.ProtoError
	Feature     = tunnel.Feature
	StatusError = tunnel.StatusError
	RemoteError = tunnel.RemoteError
)

const (
	ProtoMin    = tunnel.ProtoMin
	ProtoMax    = tunnel.ProtoMax
	StdioTarget = tunnel.StdioTarget
)

func NewWord() (string, error)                    { return tunnel.NewWord() }
func NormalizeWord(w string) (string, error)      { return tunnel.NormalizeWord(w) }
func CheckSecret(what, secret string) error       { return tunnel.CheckSecret(what, secret) }
func CheckClientToken(token string) error         { return tunnel.CheckClientToken(token) }
func ProtoRange(min, max int) string              { return tunnel.ProtoRange(min, max) }
func Negotiate(min, max int) (proto int, ok bool) { return tunnel.Negotiate(min, max) }
