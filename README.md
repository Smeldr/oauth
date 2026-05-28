# forge-oauth

OAuth 2.1 authorization server for remote MCP servers.

[![Go Reference](https://pkg.go.dev/badge/forge-cms.dev/forge-oauth.svg)](https://pkg.go.dev/forge-cms.dev/forge-oauth)
**v0.1.0 — MIT license.**

---

forge-oauth is a standalone Go library that implements an OAuth 2.1 authorization
server for use with remote [Model Context Protocol](https://modelcontextprotocol.io)
servers. ChatGPT Plus and Claude.ai require OAuth 2.1 to connect to remote MCP
servers; forge-oauth provides the server-side implementation.

## Standards

- **OAuth 2.1** (draft-15): PKCE mandatory, no implicit flow, no ROPC
- **RFC 8414**: Authorization Server Metadata
- **RFC 9728**: Protected Resource Metadata (via `forge-cms.dev/forge-mcp`)
- **CIMD**: Client ID Metadata Documents — stateless client validation

## Features

- Stateless client validation via CIMD (no client registration database)
- PKCE S256 — mandatory for all authorization requests
- Refresh tokens via `offline_access` scope (required for ChatGPT)
- HTML authorization form — user pastes their existing Forge bearer token
- SQLite storage out of the box (`modernc.org/sqlite` — no CGO)
- `slog`-based structured logging

## Installation

```
go get forge-cms.dev/forge-oauth
```

Requires Go 1.26.3+.

## Quick start

```go
import (
    "log"
    "net/http"

    "forge-cms.dev/forge"
    forgeoauth "forge-cms.dev/forge-oauth"
    forgemcp "forge-cms.dev/forge-mcp"
)

func main() {
    app := smeldr.New(smeldr.Config{...})

    store, err := forgeoauth.NewSQLiteStore("./forge-oauth.db")
    if err != nil {
        log.Fatal(err)
    }

    oauthSrv := forgeoauth.New(forgeoauth.Config{
        Issuer: "https://cms.example.com",
        VerifyBearer: func(token string) bool {
            // Validate Forge bearer token using smeldr.VerifyTokenString (v1.25.0+).
            _, ok := smeldr.VerifyTokenString(token, app.Secret(), app.TokenStore())
            return ok
        },
    }, store)

    mcpSrv := forgemcp.New(app, forgemcp.WithOAuth(oauthSrv))
    http.ListenAndServe(":8080", mcpSrv.Handler())
}
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/.well-known/oauth-authorization-server` | RFC 8414 metadata |
| `GET` | `/oauth/authorize` | Authorization form |
| `POST` | `/oauth/authorize` | Form submission |
| `POST` | `/oauth/token` | Code exchange and token refresh |

## ChatGPT / ngrok runbook

To test end-to-end with ChatGPT Plus:

1. Install ngrok: `winget install ngrok.ngrok`
2. Configure: `ngrok config add-authtoken <your-token>`
3. Start your Forge + MCP server locally on port 8080
4. Run `ngrok http 8080` — note the HTTPS URL (e.g. `https://abc123.ngrok-free.app`)
5. Set `Issuer: "https://abc123.ngrok-free.app"` in `forgeoauth.Config`
6. Restart the server with the ngrok URL
7. In ChatGPT Plus: Settings → Connected Apps → Add → paste the ngrok HTTPS URL
8. ChatGPT triggers the OAuth flow → browser opens the authorization form
9. Paste your Forge bearer token → click Approve
10. ChatGPT receives an access token and can call MCP tools (e.g. `list_posts`)

## Storage

Three SQLite tables are created automatically by `NewSQLiteStore`:

| Table | Purpose |
|-------|---------|
| `forge_oauth_codes` | Short-lived authorization codes (5 min default) |
| `forge_oauth_tokens` | Access tokens (1 hour default) |
| `forge_oauth_refresh_tokens` | Refresh tokens (no expiry in v1) |

## License

MIT — see [LICENSE](LICENSE).

Part of the [Forge CMS](https://forge-cms.dev) ecosystem.
