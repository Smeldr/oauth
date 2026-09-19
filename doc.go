// Package oauth implements an OAuth 2.1 authorization server for remote
// MCP servers. It supports the authorization code flow with mandatory PKCE
// (S256), stateless client validation via Client ID Metadata Documents (CIMD),
// and optional refresh tokens via the offline_access scope.
//
// # Standards
//
//   - OAuth 2.1 (draft-15): PKCE mandatory, no implicit flow, no ROPC
//   - RFC 8414: Authorization Server Metadata
//   - RFC 8707: Resource Indicators — audience-bound tokens via Config.Resource
//   - RFC 9207: Authorization Server Issuer Identification — iss on every redirect
//   - CIMD: stateless client validation by fetching the client_id URL
//
// # Quick start
//
//	store, err := oauth.NewSQLiteStore("./oauth.db")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	srv := oauth.New(oauth.Config{
//	    Issuer:   "https://cms.example.com",
//	    Resource: "https://cms.example.com/mcp",
//	    VerifyBearer: func(token string) bool {
//	        _, ok := smeldr.VerifyTokenString(token, app.Secret(), app.TokenStore())
//	        return ok
//	    },
//	}, store)
//
//	// srv.Handler() mounts all OAuth endpoints.
//	// Embed in a larger mux via forgemcp.WithOAuth(srv).
package oauth
