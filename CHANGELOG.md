# Changelog

All notable changes to smeldr.dev/oauth are documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
