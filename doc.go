// Package oauth implements an OAuth 2.1 authorization server for remote
// MCP servers. It supports the authorization code flow with mandatory PKCE
// (S256), client validation via Client ID Metadata Documents (CIMD) or
// Dynamic Client Registration (RFC 7591), and optional refresh tokens via
// the offline_access scope.
//
// # Standards
//
//   - OAuth 2.1 (draft-15): PKCE mandatory, no implicit flow, no ROPC
//   - RFC 8414: Authorization Server Metadata
//   - RFC 8707: Resource Indicators — audience-bound tokens via Config.Resource
//   - RFC 9207: Authorization Server Issuer Identification — iss on every redirect
//   - RFC 7591: Dynamic Client Registration — opt-in fallback for clients that
//     can't host a CIMD document; available when the configured Store
//     implements RegistrationStore (SQLiteStore does)
//   - CIMD: client validation by fetching the client_id URL — no registration
//     required for CIMD-capable clients
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
//	    ResolveBearer: func(token string) (oauth.Subject, bool) {
//	        u, ok := smeldr.VerifyTokenString(token, app.Secret(), app.TokenStore())
//	        if !ok || u.TokenID == "" {
//	            return oauth.Subject{}, false
//	        }
//	        _, exp, ok, _ := app.TokenStore().ActingUser(context.Background(), u.TokenID)
//	        return oauth.Subject{UserID: u.ID, TokenID: u.TokenID, ExpiresAt: exp}, ok
//	    },
//	    TokenActive: func(tokenID string) (oauth.Subject, bool) {
//	        u, exp, ok, _ := app.TokenStore().ActingUser(context.Background(), tokenID)
//	        return oauth.Subject{UserID: u.ID, TokenID: tokenID, ExpiresAt: exp}, ok
//	    },
//	}, store)
//
// An access token stands for exactly the Smeldr token pasted at sign-in
// (D195): smeldr.dev/mcp acts with that token's identity, class and rights at
// each request, and a scope gives nothing. Each refresh rotates the refresh
// token, and neither token outlives the Smeldr token behind it.
//
//	// srv.Handler() mounts all OAuth endpoints.
//	// Embed in a larger mux via forgemcp.WithOAuth(srv).
package oauth
