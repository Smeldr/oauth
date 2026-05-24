package forgeoauth

import (
	"encoding/json"
	"net/http"
)

// metadataHandler serves GET /.well-known/oauth-authorization-server
// per RFC 8414 — Authorization Server Metadata.
func (s *Server) metadataHandler(w http.ResponseWriter, r *http.Request) {
	meta := map[string]any{
		"issuer":                                s.cfg.Issuer,
		"authorization_endpoint":                s.cfg.Issuer + "/oauth/authorize",
		"token_endpoint":                        s.cfg.Issuer + "/oauth/token",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"mcp", "mcp:admin", "offline_access"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(meta) //nolint:errcheck
}
