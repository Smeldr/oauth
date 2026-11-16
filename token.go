package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
)

// tokenHandler handles POST /oauth/token.
// It supports two grant types:
//   - authorization_code — PKCE code exchange
//   - refresh_token      — refresh token rotation: a new access token and a new
//     refresh token; the used refresh token is refused after (T1285)
func (s *Server) tokenHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, "invalid_request", "could not parse form body")
		return
	}

	grantType := r.FormValue("grant_type")
	switch grantType {
	case "authorization_code":
		s.handleCodeExchange(w, r)
	case "refresh_token":
		s.handleRefreshToken(w, r)
	default:
		writeTokenError(w, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
	}
}

// handleCodeExchange processes the authorization_code grant.
func (s *Server) handleCodeExchange(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	addr := r.RemoteAddr

	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")
	resource := r.FormValue("resource")

	if code == "" || clientID == "" || redirectURI == "" || codeVerifier == "" || resource == "" {
		writeTokenError(w, "invalid_request", "missing required parameter")
		return
	}

	stored, err := s.store.GetCode(ctx, code)
	if err != nil {
		writeTokenError(w, "invalid_grant", "authorization code not found")
		return
	}

	// Always delete the code — single use, even on failure.
	_ = s.store.DeleteCode(ctx, code)

	if s.now().After(stored.ExpiresAt) {
		slog.Warn("oauth: authorization code expired",
			"client_id", clientID,
			"remote_addr", addr,
		)
		writeTokenError(w, "invalid_grant", "authorization code expired")
		return
	}

	if !VerifyPKCE(codeVerifier, stored.CodeChallenge) {
		slog.Warn("oauth: invalid code_verifier",
			"client_id", clientID,
			"remote_addr", addr,
		)
		writeTokenError(w, "invalid_grant", "invalid code_verifier")
		return
	}

	if stored.ClientID != clientID {
		writeTokenError(w, "invalid_grant", "client_id mismatch")
		return
	}
	if stored.RedirectURI != redirectURI {
		writeTokenError(w, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if stored.Resource != resource {
		writeTokenError(w, "invalid_target", "resource does not match authorization request")
		return
	}

	// D195: a code with no subject (made before it, or by an old wiring)
	// gives no access token; the subject is checked again here, so a token
	// revoked between the form and the exchange gets none.
	subject, ok := s.activeSubject(stored.UserID, stored.TokenID)
	if !ok {
		writeTokenError(w, "invalid_grant", "the sign-in's token is no longer valid; sign in again")
		return
	}

	accessToken := newToken(32)

	expires := earlier(s.now().Add(s.cfg.AccessTokenTTL), subject.ExpiresAt)
	ttl := expires.Sub(s.now())
	at := AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		Scope:     stored.Scope,
		Resource:  stored.Resource,
		ExpiresAt: expires,
		UserID:    subject.UserID,
		TokenID:   subject.TokenID,
	}
	if err := s.store.SaveToken(ctx, at); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	slog.Info("oauth: access token issued",
		"client_id", clientID,
		"scope", stored.Scope,
		"expires_in", int(ttl.Seconds()),
	)

	resp := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(ttl.Seconds()),
		"scope":        stored.Scope,
	}

	// Issue refresh token when offline_access scope is present.
	if containsScope(stored.Scope, "offline_access") {
		refreshToken := newToken(32)
		rt := RefreshToken{
			Token:     refreshToken,
			ClientID:  clientID,
			Scope:     stored.Scope,
			ExpiresAt: earlier(s.now().Add(s.cfg.RefreshTokenTTL), subject.ExpiresAt),
			UserID:    subject.UserID,
			TokenID:   subject.TokenID,
		}
		if err := s.store.SaveRefreshToken(ctx, rt); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		resp["refresh_token"] = refreshToken
	}

	writeTokenResponse(w, resp)
}

// handleRefreshToken processes the refresh_token grant.
func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	addr := r.RemoteAddr

	refreshToken := r.FormValue("refresh_token")
	clientID := r.FormValue("client_id")

	if refreshToken == "" || clientID == "" {
		writeTokenError(w, "invalid_request", "missing required parameter")
		return
	}

	stored, err := s.store.GetRefreshToken(ctx, refreshToken)
	if err != nil {
		writeTokenError(w, "invalid_grant", "refresh token not found")
		return
	}

	if stored.ClientID != clientID {
		writeTokenError(w, "invalid_grant", "client_id mismatch")
		return
	}
	// A refresh token with no expiry (made before it existed) or past it is
	// refused and removed.
	if stored.ExpiresAt.IsZero() || !s.now().Before(stored.ExpiresAt) {
		_ = s.store.DeleteRefreshToken(ctx, refreshToken)
		writeTokenError(w, "invalid_grant", "refresh token expired")
		return
	}
	// D195: the token behind it must still be valid.
	subject, ok := s.activeSubject(stored.UserID, stored.TokenID)
	if !ok {
		_ = s.store.DeleteRefreshToken(ctx, refreshToken)
		writeTokenError(w, "invalid_grant", "the sign-in's token is no longer valid; sign in again")
		return
	}

	// Rotation (T1285): a new refresh token, and the used one is gone, in
	// one step where the store can, so two uses of one token cannot both
	// succeed.
	next := RefreshToken{
		Token:     newToken(32),
		ClientID:  clientID,
		Scope:     stored.Scope,
		ExpiresAt: earlier(stored.ExpiresAt, subject.ExpiresAt),
		UserID:    subject.UserID,
		TokenID:   subject.TokenID,
	}
	if err := s.rotateRefreshToken(ctx, refreshToken, next); err != nil {
		if errors.Is(err, ErrRefreshTokenNotFound) {
			writeTokenError(w, "invalid_grant", "refresh token not found")
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	accessToken := newToken(32)
	expires := earlier(s.now().Add(s.cfg.AccessTokenTTL), subject.ExpiresAt)
	ttl := expires.Sub(s.now())
	at := AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		Scope:     stored.Scope,
		Resource:  s.cfg.Resource,
		ExpiresAt: expires,
		UserID:    subject.UserID,
		TokenID:   subject.TokenID,
	}
	if err := s.store.SaveToken(ctx, at); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	slog.Info("oauth: refresh token used",
		"client_id", clientID,
		"remote_addr", addr,
	)

	writeTokenResponse(w, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(ttl.Seconds()),
		"scope":         stored.Scope,
		"refresh_token": next.Token,
	})
}

// activeSubject re-reads the subject behind userID and tokenID through
// [Config.TokenActive]: false when there is no subject, the wiring cannot
// check it, the token is no longer valid, or it now belongs to someone else.
func (s *Server) activeSubject(userID, tokenID string) (Subject, bool) {
	if userID == "" || tokenID == "" || s.cfg.TokenActive == nil {
		return Subject{}, false
	}
	sub, ok := s.cfg.TokenActive(tokenID)
	if !ok || sub.UserID != userID {
		return Subject{}, false
	}
	sub.TokenID = tokenID
	return sub, true
}

// rotateRefreshToken replaces old with next: atomically when the store can
// (refreshRotator), else by deleting old and saving next.
func (s *Server) rotateRefreshToken(ctx context.Context, old string, next RefreshToken) error {
	if r, ok := s.store.(refreshRotator); ok {
		return r.RotateRefreshToken(ctx, old, next)
	}
	if err := s.store.DeleteRefreshToken(ctx, old); err != nil {
		return err
	}
	return s.store.SaveRefreshToken(ctx, next)
}

// writeTokenResponse writes a JSON token response with cache-control headers.
func writeTokenResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

// writeTokenError writes an RFC 6749 JSON error response with HTTP 400.
func writeTokenError(w http.ResponseWriter, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"error":             errCode,
		"error_description": description,
	})
}

// containsScope reports whether scope (a space-separated list) contains target.
func containsScope(scope, target string) bool {
	for _, s := range strings.Fields(scope) {
		if s == target {
			return true
		}
	}
	return false
}
