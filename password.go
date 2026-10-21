package main

// Password hashes, for the console and [[basic_auth]]. Two formats are read:
//
//	$argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>$<salt b64>$<hash b64>   (PHC string, as the argon2 CLI prints)
//	pbkdf2-sha256$<iterations>$<salt b64>$<hash b64>                    (older versions of this proxy)
//
// New hashes are argon2id.

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// pbkdf2Iterations follows OWASP's 2023 guidance for PBKDF2-SHA256.
// Lowered in tests.
var pbkdf2Iterations = 600_000

// argon2Memory (KiB), argon2Passes and argon2Lanes are RFC 9106's second
// recommended setting (64 MiB, 3 passes). Lowered in tests.
var (
	argon2Memory uint32 = 64 * 1024
	argon2Passes uint32 = 3
	argon2Lanes  uint8  = 4
)

const (
	hashPrefix   = "pbkdf2-sha256"
	argon2Prefix = "$argon2id$"
)

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argon2Passes, argon2Memory, argon2Lanes, 32)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("%sv=%d$m=%d,t=%d,p=%d$%s$%s", argon2Prefix, argon2.Version, argon2Memory, argon2Passes, argon2Lanes,
		enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// validHash says why a hash cannot be checked against, nil if it can.
func validHash(hash string) error {
	if strings.HasPrefix(hash, argon2Prefix) {
		_, err := parseArgon2(hash)
		return err
	}
	_, _, _, err := parseHash(hash)
	return err
}

func parseHash(hash string) (iter int, salt, key []byte, err error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != hashPrefix {
		return 0, nil, nil, fmt.Errorf("not an argon2id or %s hash (generate one with: tlsproxy --hash-password)", hashPrefix)
	}
	if iter, err = strconv.Atoi(parts[1]); err != nil || iter < 1000 {
		return 0, nil, nil, fmt.Errorf("bad iteration count in password hash")
	}
	enc := base64.RawStdEncoding
	if salt, err = enc.DecodeString(parts[2]); err != nil || len(salt) < 8 {
		return 0, nil, nil, fmt.Errorf("bad salt in password hash")
	}
	if key, err = enc.DecodeString(parts[3]); err != nil || len(key) < 16 {
		return 0, nil, nil, fmt.Errorf("bad key in password hash")
	}
	return iter, salt, key, nil
}

type argon2Params struct {
	memory, passes uint32
	lanes          uint8
	salt, key      []byte
}

// parseArgon2 reads a $argon2id$ PHC string. Its cost is capped, so a hash
// someone pastes cannot make each check take gigabytes.
func parseArgon2(hash string) (p argon2Params, err error) {
	bad := func(what string) (argon2Params, error) {
		return argon2Params{}, fmt.Errorf("bad argon2id hash: %s (expected $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>)", what)
	}
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return bad("wrong number of $ parts")
	}
	if parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return bad("version " + parts[2] + ", only v=19 is supported")
	}
	var m, t, l uint64
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, _ := strings.Cut(kv, "=")
		n, perr := strconv.ParseUint(v, 10, 32)
		if perr != nil {
			return bad("parameter " + kv)
		}
		switch k {
		case "m":
			m = n
		case "t":
			t = n
		case "p":
			l = n
		default:
			return bad("parameter " + kv)
		}
	}
	switch {
	case m < 8 || m > 1<<20:
		return bad("m (memory in KiB) must be 8..1048576")
	case t < 1 || t > 100:
		return bad("t (passes) must be 1..100")
	case l < 1 || l > 64:
		return bad("p (lanes) must be 1..64")
	}
	enc := base64.RawStdEncoding
	if p.salt, err = enc.DecodeString(parts[4]); err != nil || len(p.salt) < 8 {
		return bad("salt")
	}
	if p.key, err = enc.DecodeString(parts[5]); err != nil || len(p.key) < 16 {
		return bad("hash")
	}
	p.memory, p.passes, p.lanes = uint32(m), uint32(t), uint8(l)
	return p, nil
}

// checkPassword compares in constant time.
func checkPassword(hash, password string) bool {
	if strings.HasPrefix(hash, argon2Prefix) {
		p, err := parseArgon2(hash)
		if err != nil {
			return false
		}
		got := argon2.IDKey([]byte(password), p.salt, p.passes, p.memory, p.lanes, uint32(len(p.key)))
		return subtle.ConstantTimeCompare(got, p.key) == 1
	}
	iter, salt, want, err := parseHash(hash)
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}
