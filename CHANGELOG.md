# Changelog

All notable changes to smeldr.dev/oauth are documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.4.0] — 2026-07-29

### Added (breaking)

- `Config.Resource` — the canonical resource identifier this authorization
  server issues audience-bound tokens for (RFC 8707 — Resource Indicators for
  OAuth 2.0). **Required — `New` now panics if empty**, mirroring the existing
  `Issuer`/`VerifyBearer` required-field checks.
- `resource` parameter now required at both `GET/POST /oauth/authorize` and
  `POST /oauth/token`. Requests with a missing or mismatched resource are
  rejected: `invalid_request` (missing) at `/oauth/authorize` (plain 400, same
  style as every other validation failure in that handler) and at
  `/oauth/token` (JSON body); `invalid_target` (RFC 8707's own error code) at
  both endpoints when the resource doesn't match `Config.Resource` or the
  authorization request's own resource.
- `AuthCode.Resource` and `AccessToken.Resource` fields — persisted through
  the full code → token flow. Refresh-token grants re-issue for the server's
  single configured `Config.Resource` (this server only ever pairs with one
  resource server; no client-supplied resource in that flow).
- `iss` parameter now always included in the `/oauth/authorize` redirect
  (RFC 9207 — Authorization Server Issuer Identification). Metadata gains
  `authorization_response_iss_parameter_supported: true`.
- SQLite schema: `resource` column added to `smeldr_oauth_codes` and
  `smeldr_oauth_tokens`. Existing databases are migrated automatically at
  startup via an idempotent `ALTER TABLE ... ADD COLUMN` pass (same pattern as
  the v0.3.0 table-rename migration), so no action is required for existing
  installs beyond adding `Config.Resource`.

### Migration from v0.3.x

Add `Resource` to your `oauth.Config` — it must match the `resource` field
your paired `smeldr.dev/mcp` instance serves at
`/.well-known/oauth-protected-resource` (typically `<base-url>/mcp`):

```go
oauthSrv := oauth.New(oauth.Config{
    Issuer:   "https://cms.example.com",
    Resource: "https://cms.example.com/mcp",
    VerifyBearer: ...,
}, store)
```

---

## [0.3.0] — 2026-06-11

### Changed

- SQLite table names renamed from `forge_oauth_*` to `smeldr_oauth_*`.
  Existing databases are migrated automatically at startup via an idempotent
  `ALTER TABLE … RENAME TO` pass that runs before the `CREATE TABLE IF NOT EXISTS`
  statements in `NewSQLiteStore`. No action required for fresh installs.

---

## [0.2.0] — 2026-06-06

### Changed (breaking)

- Package renamed `forgeoauth` → `oauth`. Update imports from `forgeoauth.X` to
  `oauth.X` (or drop the alias: `import "smeldr.dev/oauth"`). No exported symbols
  changed — only the package qualifier at call sites.
- Error string prefixes updated from `forgeoauth:` to `oauth:` throughout
  (sentinels, panics, and wrapped errors).

---

## [0.1.5] — 2026-05-30

### Changed

- Authorization form, error messages, comments, README, and LICENSE: "Forge" → "Smeldr"
  brand update throughout.

---

## [0.1.0] — 2026-05-24

Initial release. OAuth 2.1 authorization server for remote MCP servers.

### Added

- `Server` — OAuth 2.1 authorization server with PKCE (S256) and CIMD stateless client validation
- `Config` — issuer URL, token TTLs, bearer verification callback, HTTP client override
- `Server.Handler()` — mounts four OAuth endpoints on an `http.ServeMux`
- `Server.ValidateAccessToken(ctx, token)` — validates a Bearer access token; returns `ErrTokenNotFound` / `ErrTokenExpired` on failure
- `Server.Issuer()` — returns the configured issuer URL (for RFC 9728 protected resource metadata)
- `Store` interface — `AuthCode`, `AccessToken`, `RefreshToken` persistence
- `SQLiteStore` — SQLite-backed `Store` implementation (`modernc.org/sqlite`)
- `NewSQLiteStore(path)` — creates tables and opens DB; use `":memory:"` for tests
- `VerifyPKCE(verifier, challenge)` — constant-time S256 PKCE verification
- RFC 8414 metadata: `GET /.well-known/oauth-authorization-server`
- Authorization endpoint: `GET /oauth/authorize` (HTML form), `POST /oauth/authorize` (form submit)
- Token endpoint: `POST /oauth/token` (authorization_code + refresh_token grant types)
- `offline_access` scope support: refresh token issued when requested
- CIMD client: stateless client validation by fetching the `client_id` HTTPS URL
- `slog`-based structured logging (Warn for security events, Info for operational events)
- Sentinel errors: `ErrTokenNotFound`, `ErrTokenExpired`, `ErrCodeNotFound`, `ErrRefreshTokenNotFound`
- Unit tests (Lag 1): 17 tests covering all endpoints and error paths
- Integration test (Lag 2): full authorization code flow end-to-end
