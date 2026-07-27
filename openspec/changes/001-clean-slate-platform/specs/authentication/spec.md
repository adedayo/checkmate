# Spec: Authentication

**Change:** 001-clean-slate-platform
**Status:** Draft

## Overview

CheckMate uses dual-mode authentication:

1. **JWT Bearer tokens** — for human/interactive sessions
2. **Scoped API keys** — for CI/headless/machine-to-machine

Both mechanisms share the same `Authorization: Bearer <token>` header. The server distinguishes them by prefix (`cm_` = API key, otherwise = JWT).

## JWT Flow

```
POST /v1/auth/token
  body: { username, password }
  response: { accessToken (15min TTL), refreshToken (7d TTL), expiresIn }

POST /v1/auth/refresh
  body: { refreshToken }
  response: { accessToken, expiresIn }

POST /v1/auth/logout
  (revokes refresh token)
```

Access tokens are signed with `CHECKMATE_JWT_SECRET` (required in production; error on startup if unset). The algorithm is HS256 minimum; RS256 supported for multi-node setups.

## API Key Design

- Created by an authenticated user via `POST /v1/auth/api-keys`
- Returned once in full as `cm_<base62-encoded-secret>` — never retrievable again
- Stored as a bcrypt hash (`bcrypt.DefaultCost`) — CheckMate never holds plaintext after creation
- Key prefix (first 8 chars, `cm_a1b2c3d4`) is stored for identification in UIs
- Each key has named scopes: `scan:read`, `scan:write`, `exception:read`, `exception:write`, `admin`
- Optional: expiry date, IP allowlist (CIDR ranges)
- Revocation: `DELETE /v1/auth/api-keys/{keyId}` — immediate effect

## Dev Mode

When `CHECKMATE_DEV_MODE=true`, all authentication is bypassed. Default when `--bind` resolves to localhost. Production containers must set `CHECKMATE_JWT_SECRET` or the server refuses to start.

## LDAP

`POST /v1/auth/ldap/sync` — delegates to the existing `ldap-sync` integration. User accounts are LDAP-authoritative when configured.
