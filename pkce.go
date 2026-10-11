package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
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
// as a lowercase hex string. Used for auth codes, access tokens, refresh
// tokens and registered client IDs.
//
// It cannot fail: since Go 1.24, crypto/rand.Read "never returns an error,
// and always fills b entirely", and crashes the program if the operating
// system's source fails. So there is no error to return.
func newToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
