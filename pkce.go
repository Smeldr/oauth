package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// VerifyPKCE checks that BASE64URL(SHA256(codeVerifier)) equals codeChallenge.
// Uses constant-time comparison to prevent timing attacks.
// Returns true when the verifier is valid (S256 method only).
func VerifyPKCE(codeVerifier, codeChallenge string) bool {
	h := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(codeChallenge)) == 1
}

// newToken generates n cryptographically random bytes and returns them
// as a lowercase hex string. Used for auth codes, access tokens, and
// refresh tokens.
func newToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth: generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}
