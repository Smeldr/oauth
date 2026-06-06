package oauth

import (
	"context"
	"time"
)

// Store provides persistence for OAuth 2.1 state: authorization codes, access
// tokens, and refresh tokens. All implementations must be safe for concurrent
// use. [SQLiteStore] is the bundled production implementation.
type Store interface {
	// SaveCode persists an authorization code.
	SaveCode(ctx context.Context, c AuthCode) error
	// GetCode retrieves an authorization code by its code value.
	// Returns [ErrCodeNotFound] if the code does not exist.
	GetCode(ctx context.Context, code string) (AuthCode, error)
	// DeleteCode removes an authorization code (e.g. after single use).
	DeleteCode(ctx context.Context, code string) error

	// SaveToken persists an access token.
	SaveToken(ctx context.Context, t AccessToken) error
	// GetToken retrieves an access token by its token value.
	// Returns [ErrTokenNotFound] if the token does not exist.
	GetToken(ctx context.Context, token string) (AccessToken, error)

	// SaveRefreshToken persists a refresh token.
	SaveRefreshToken(ctx context.Context, t RefreshToken) error
	// GetRefreshToken retrieves a refresh token by its token value.
	// Returns [ErrRefreshTokenNotFound] if the token does not exist.
	GetRefreshToken(ctx context.Context, token string) (RefreshToken, error)
	// DeleteRefreshToken removes a refresh token.
	DeleteRefreshToken(ctx context.Context, token string) error
}

// AuthCode is a short-lived, single-use PKCE authorization code.
type AuthCode struct {
	// Code is the raw authorization code value (random hex, 32 bytes).
	Code string
	// ClientID is the HTTPS URL identifying the OAuth client (CIMD).
	ClientID string
	// RedirectURI is the callback URL for this authorization request.
	RedirectURI string
	// Scope is the space-separated scope string requested by the client.
	Scope string
	// CodeChallenge is BASE64URL(SHA256(code_verifier)) (S256 method).
	CodeChallenge string
	// ExpiresAt is the UTC time after which this code must be rejected.
	ExpiresAt time.Time
}

// AccessToken is a Bearer access token issued after code exchange.
type AccessToken struct {
	// Token is the raw token value.
	Token string
	// ClientID is the HTTPS URL identifying the OAuth client.
	ClientID string
	// Scope is the space-separated scope string for this token.
	Scope string
	// ExpiresAt is the UTC time after which this token is invalid.
	ExpiresAt time.Time
}

// RefreshToken is a long-lived token used to obtain new access tokens.
// In v1, refresh tokens do not expire. They are issued only when the
// authorization request includes the [offline_access] scope.
type RefreshToken struct {
	// Token is the raw token value.
	Token string
	// ClientID is the HTTPS URL identifying the OAuth client.
	ClientID string
	// Scope is the space-separated scope string for this token.
	Scope string
}
