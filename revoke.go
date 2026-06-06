package oauth

import "net/http"

// revokeHandler handles POST /oauth/revoke per RFC 7009.
//
// The response is always 200 OK — even when the token is unknown or already
// revoked. This is required by the spec: the client should not be able to
// infer whether a token was valid from the response.
//
// Only refresh tokens are handled. Access tokens expire naturally via
// [AccessToken.ExpiresAt] and are not stored in a revocable form.
// Supplying an access token via the token parameter is silently ignored
// (RFC 7009 §2.2 allows this).
//
// The optional token_type_hint parameter is accepted but not enforced —
// RFC 7009 §2.1 treats it as a performance hint only.
func (s *Server) revokeHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		// ParseForm failure is non-fatal — respond 200 per spec.
		w.WriteHeader(http.StatusOK)
		return
	}
	token := r.FormValue("token")
	if token != "" {
		// Best-effort deletion. Ignore ErrRefreshTokenNotFound and all other
		// errors — RFC 7009 requires 200 OK in every case.
		_ = s.store.DeleteRefreshToken(r.Context(), token)
	}
	w.WriteHeader(http.StatusOK)
}
