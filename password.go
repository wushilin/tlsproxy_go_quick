package main

// Console password hashing: PBKDF2-HMAC-SHA256 from the standard library.
// Stored as  pbkdf2-sha256$<iterations>$<salt b64>$<hash b64>.

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// pbkdf2Iterations follows OWASP's 2023 guidance for PBKDF2-SHA256.
// Lowered in tests.
var pbkdf2Iterations = 600_000

const hashPrefix = "pbkdf2-sha256"

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, 32)
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("%s$%d$%s$%s", hashPrefix, pbkdf2Iterations, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

func parseHash(hash string) (iter int, salt, key []byte, err error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != hashPrefix {
		return 0, nil, nil, fmt.Errorf("not a %s hash (generate one with: tlsproxy --hash-password)", hashPrefix)
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

// checkPassword compares in constant time.
func checkPassword(hash, password string) bool {
	iter, salt, want, err := parseHash(hash)
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}
