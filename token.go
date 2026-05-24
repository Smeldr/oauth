package forgeoauth

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// tokenHandler handles POST /oauth/token.
// It supports two grant types:
//   - authorization_code — PKCE code exchange
//   - refresh_token      — refresh token rotation (new access token)
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

	if code == "" || clientID == "" || redirectURI == "" || codeVerifier == "" {
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
		slog.Warn("forge-oauth: authorization code expired",
			"client_id", clientID,
			"remote_addr", addr,
		)
		writeTokenError(w, "invalid_grant", "authorization code expired")
		return
	}

	if !VerifyPKCE(codeVerifier, stored.CodeChallenge) {
		slog.Warn("forge-oauth: invalid code_verifier",
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

	accessToken, err := newToken(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	ttl := s.cfg.AccessTokenTTL
	at := AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		Scope:     stored.Scope,
		ExpiresAt: s.now().Add(ttl),
	}
	if err := s.store.SaveToken(ctx, at); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	slog.Info("forge-oauth: access token issued",
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
		refreshToken, err := newToken(32)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		rt := RefreshToken{
			Token:    refreshToken,
			ClientID: clientID,
			Scope:    stored.Scope,
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

	accessToken, err := newToken(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	ttl := s.cfg.AccessTokenTTL
	at := AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		Scope:     stored.Scope,
		ExpiresAt: s.now().Add(ttl),
	}
	if err := s.store.SaveToken(ctx, at); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	slog.Info("forge-oauth: refresh token used",
		"client_id", clientID,
		"remote_addr", addr,
	)

	writeTokenResponse(w, map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(ttl.Seconds()),
		"scope":        stored.Scope,
	})
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
