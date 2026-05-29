// Package forgeoauth implements an OAuth 2.1 authorization server for remote
// MCP servers. It supports the authorization code flow with mandatory PKCE
// (S256), stateless client validation via Client ID Metadata Documents (CIMD),
// and optional refresh tokens via the offline_access scope.
//
// # Standards
//
//   - OAuth 2.1 (draft-15): PKCE mandatory, no implicit flow, no ROPC
//   - RFC 8414: Authorization Server Metadata
//   - CIMD: stateless client validation by fetching the client_id URL
//
// # Quick start
//
//	store, err := forgeoauth.NewSQLiteStore("./oauth.db")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	srv := forgeoauth.New(forgeoauth.Config{
//	    Issuer: "https://cms.example.com",
//	    VerifyBearer: func(token string) bool {
//	        _, ok := smeldr.VerifyTokenString(token, app.Secret(), app.TokenStore())
//	        return ok
//	    },
//	}, store)
//
//	// srv.Handler() mounts all OAuth endpoints.
//	// Embed in a larger mux via forgemcp.WithOAuth(srv).
package forgeoauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Sentinel errors returned by [Server.ValidateAccessToken].
var (
	// ErrTokenNotFound is returned when the access token does not exist in the store.
	ErrTokenNotFound = errors.New("forgeoauth: access token not found")
	// ErrTokenExpired is returned when the access token exists but has passed its ExpiresAt.
	ErrTokenExpired = errors.New("forgeoauth: access token expired")
	// ErrCodeNotFound is returned by [Store.GetCode] when the code does not exist.
	ErrCodeNotFound = errors.New("forgeoauth: authorization code not found")
	// ErrRefreshTokenNotFound is returned by [Store.GetRefreshToken] when the token does not exist.
	ErrRefreshTokenNotFound = errors.New("forgeoauth: refresh token not found")
)

// Config holds the configuration for the OAuth 2.1 authorization server.
type Config struct {
	// Issuer is the HTTPS base URL of this authorization server.
	// Included in RFC 8414 metadata and in WWW-Authenticate headers.
	// Example: "https://cms.example.com"
	// Required — New panics if empty.
	Issuer string

	// AccessTokenTTL is how long access tokens remain valid.
	// Default: 1 hour.
	AccessTokenTTL time.Duration

	// AuthCodeTTL is how long authorization codes remain valid.
	// Default: 5 minutes.
	AuthCodeTTL time.Duration

	// VerifyBearer validates a Forge bearer token submitted at /oauth/authorize.
	// Returns true if the token authenticates a valid user on the Forge site.
	// Required — New panics if nil.
	//
	// Example using smeldr.VerifyTokenString (smeldr.dev/core v1.25.0+):
	//
	//	VerifyBearer: func(token string) bool {
	//	    _, ok := smeldr.VerifyTokenString(token, app.Secret(), app.TokenStore())
	//	    return ok
	//	},
	VerifyBearer func(token string) bool

	// HTTPClient is used for CIMD metadata fetches.
	// Default: &http.Client{Timeout: 5 * time.Second}.
	HTTPClient *http.Client
}

// Server is an OAuth 2.1 authorization server.
// Create with [New]; use [Handler] to mount endpoints.
type Server struct {
	cfg   Config
	store Store
	now   func() time.Time // injectable for tests
}

// New creates a Server with the given configuration and store.
// Panics if cfg.Issuer is empty or cfg.VerifyBearer is nil.
func New(cfg Config, store Store) *Server {
	if cfg.Issuer == "" {
		panic("forgeoauth: Config.Issuer must not be empty")
	}
	if cfg.VerifyBearer == nil {
		panic("forgeoauth: Config.VerifyBearer must not be nil")
	}
	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = time.Hour
	}
	if cfg.AuthCodeTTL <= 0 {
		cfg.AuthCodeTTL = 5 * time.Minute
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &Server{
		cfg:   cfg,
		store: store,
		now:   time.Now,
	}
}

// Handler returns an http.Handler that serves all OAuth 2.1 endpoints:
//
//	GET  /.well-known/oauth-authorization-server  — RFC 8414 metadata
//	GET  /oauth/authorize                          — authorization form
//	POST /oauth/authorize                          — form submission
//	POST /oauth/token                              — code exchange and token refresh
//	POST /oauth/revoke                             — RFC 7009 token revocation
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.metadataHandler)
	mux.HandleFunc("GET /oauth/authorize", s.authorizeGetHandler)
	mux.HandleFunc("POST /oauth/authorize", s.authorizePostHandler)
	mux.HandleFunc("POST /oauth/token", s.tokenHandler)
	mux.HandleFunc("POST /oauth/revoke", s.revokeHandler)
	return mux
}

// ValidateAccessToken looks up a Bearer access token in the store.
// Returns the [AccessToken] record on success.
// Returns [ErrTokenNotFound] if the token is unknown, or [ErrTokenExpired]
// if the token exists but has passed its ExpiresAt time.
func (s *Server) ValidateAccessToken(ctx context.Context, token string) (*AccessToken, error) {
	at, err := s.store.GetToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTokenNotFound, err)
	}
	if s.now().After(at.ExpiresAt) {
		return nil, ErrTokenExpired
	}
	return &at, nil
}

// Issuer returns the server's configured issuer URL.
// Used by forge-mcp to populate the authorization_servers field in
// /.well-known/oauth-protected-resource (RFC 9728).
func (s *Server) Issuer() string {
	return s.cfg.Issuer
}
