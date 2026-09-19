# smeldr.dev/oauth

OAuth 2.1 authorization server for remote MCP servers.

[![Go Reference](https://pkg.go.dev/badge/smeldr.dev/oauth.svg)](https://pkg.go.dev/smeldr.dev/oauth)
**v0.5.0 — MIT license.**

---

smeldr.dev/oauth is a standalone Go library that implements an OAuth 2.1 authorization
server for use with remote [Model Context Protocol](https://modelcontextprotocol.io)
servers. ChatGPT Plus and Claude.ai require OAuth 2.1 to connect to remote MCP
servers; smeldr.dev/oauth provides the server-side implementation.

## Standards

- **OAuth 2.1** (draft-15): PKCE mandatory, no implicit flow, no ROPC
- **RFC 8414**: Authorization Server Metadata
- **RFC 8707**: Resource Indicators — audience-bound tokens via `Config.Resource`
- **RFC 9207**: Authorization Server Issuer Identification — `iss` on every redirect
- **RFC 9728**: Protected Resource Metadata (via `smeldr.dev/mcp`)
- **RFC 7591**: Dynamic Client Registration — opt-in fallback for clients that can't host a CIMD document
- **CIMD**: Client ID Metadata Documents — stateless client validation

## Features

- Stateless client validation via CIMD (no registration required for CIMD-capable clients) — Dynamic Client Registration (RFC 7591) available as an opt-in fallback for clients that can't host one
- PKCE S256 — mandatory for all authorization requests
- Refresh tokens via `offline_access` scope (required for ChatGPT)
- HTML authorization form — user pastes their Smeldr bearer token
- SQLite storage out of the box (`modernc.org/sqlite` — no CGO)
- `slog`-based structured logging

## Installation

```
go get smeldr.dev/oauth
```

Requires Go 1.26.3+.

## Migrating from v0.1.x

The package was renamed from `forgeoauth` to `oauth` in v0.2.0.
Replace `forgeoauth.X` → `oauth.X` at all call sites (or drop the alias:
`import "smeldr.dev/oauth"`).

## Quick start

```go
import (
    "log"
    "net/http"

    "smeldr.dev/core"
    "smeldr.dev/oauth"
    forgemcp "smeldr.dev/mcp"
)

func main() {
    app := smeldr.New(smeldr.Config{...})

    store, err := oauth.NewSQLiteStore("./oauth.db")
    if err != nil {
        log.Fatal(err)
    }

    oauthSrv := oauth.New(oauth.Config{
        Issuer:   "https://cms.example.com",
        Resource: "https://cms.example.com/mcp", // must match smeldr.dev/mcp's own resource identifier
        VerifyBearer: func(token string) bool {
            // Validate Smeldr bearer token using smeldr.VerifyTokenString (v1.25.0+).
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
| `POST` | `/oauth/revoke` | RFC 7009 token revocation |
| `POST` | `/oauth/register` | RFC 7591 Dynamic Client Registration (only when the configured `Store` implements `RegistrationStore`) |

## ChatGPT / ngrok runbook

To test end-to-end with ChatGPT Plus:

1. Install ngrok: `winget install ngrok.ngrok`
2. Configure: `ngrok config add-authtoken <your-token>`
3. Start your Smeldr + MCP server locally on port 8080
4. Run `ngrok http 8080` — note the HTTPS URL (e.g. `https://abc123.ngrok-free.app`)
5. Set `Issuer: "https://abc123.ngrok-free.app"` in `oauth.Config`
6. Restart the server with the ngrok URL
7. In ChatGPT Plus: Settings → Connected Apps → Add → paste the ngrok HTTPS URL
8. ChatGPT triggers the OAuth flow → browser opens the authorization form
9. Paste your Smeldr bearer token → click Approve
10. ChatGPT receives an access token and can call MCP tools (e.g. `list_posts`)

## Storage

Four SQLite tables are created automatically by `NewSQLiteStore`:

| Table | Purpose |
|-------|---------|
| `smeldr_oauth_codes` | Short-lived authorization codes (5 min default) |
| `smeldr_oauth_tokens` | Access tokens (1 hour default) |
| `smeldr_oauth_refresh_tokens` | Refresh tokens (no expiry in v1) |
| `smeldr_oauth_registered_clients` | Dynamic Client Registration records (RFC 7591) — permanent, bounded by `MaxRegisteredClients` |

## License

MIT — see [LICENSE](LICENSE).

Part of the [Smeldr](https://smeldr.dev) ecosystem.
