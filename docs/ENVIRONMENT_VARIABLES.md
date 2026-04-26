# Environment Variables

All configuration variables use the `GVMR_` prefix.

---

## Core Configuration

| Variable                       |                                         Default | Description                                                        |
| ------------------------------ | ----------------------------------------------: | ------------------------------------------------------------------ |
| `GVMR_PORT`                    |                                          `8084` | HTTP server port                                                   |
| `GVMR_REPORT_FORMATS_FEED_DIR` | `/var/lib/gvm/data-objects/gvmd/report-formats` | Source directory containing report format files and related assets |
| `GVMR_WORK_DIR`                |                           `/tmp/gvmr-lite/work` | Working directory used by the service                              |
| `GVMR_REBUILD_ON_START`        |                                          `true` | Rebuild or rematerialize cached report formats on startup          |
| `GVMR_MAX_BODY_BYTES`          |                                      `52428800` | Maximum accepted HTTP request body size in bytes                   |

Derived internally:

```text
report_formats_work_dir = GVMR_WORK_DIR/report-formats
```

---

## Authentication

| Variable         | Default | Description                                      |
| ---------------- | ------: | ------------------------------------------------ |
| `GVMR_AUTH_MODE` |  `none` | Authentication mode: `none`, `api_key`, or `jwt` |

---

## API Key Authentication

Used when:

```env
GVMR_AUTH_MODE=api_key
```

| Variable              |     Default | Description                          |
| --------------------- | ----------: | ------------------------------------ |
| `GVMR_API_KEY`        |   _(empty)_ | Shared API key value                 |
| `GVMR_API_KEY_HEADER` | `X-API-Key` | Header name used to read the API key |

Expected behavior:

- missing or invalid API key -> `401 Unauthorized`
- missing required server-side API key config -> `500 Internal Server Error`

---

## JWT Authentication

Used when:

```env
GVMR_AUTH_MODE=jwt
```

| Variable                      |     Default | Description                            |
| ----------------------------- | ----------: | -------------------------------------- |
| `GVMR_JWT_SECRET`             |   _(empty)_ | Shared secret for HS256 JWT validation |
| `GVMR_JWT_AUDIENCE`           | `gvmr-lite` | Expected JWT audience (`aud`)          |
| `GVMR_JWT_ISSUER`             | `gvmd-lite` | Expected JWT issuer (`iss`)            |
| `GVMR_JWT_CLOCK_SKEW_SECONDS` |       `300` | Allowed clock skew in seconds          |

Supported JWT scope claim formats:

- `scope: "render sync"`
- `scopes: ["render", "sync"]`

Expected behavior:

- missing or invalid token -> `401 Unauthorized`
- missing required scope -> `403 Forbidden`
- missing required JWT server config -> `500 Internal Server Error`

---

## Authorization Scopes

| Variable                     |  Default | Description                                                     |
| ---------------------------- | -------: | --------------------------------------------------------------- |
| `GVMR_REQUIRED_SCOPE_RENDER` | `render` | Required scope for render endpoints in JWT mode                 |
| `GVMR_REQUIRED_SCOPE_SYNC`   |   `sync` | Required scope for sync and report format endpoints in JWT mode |

---

## Logging

| Variable          |  Default | Description                                          |
| ----------------- | -------: | ---------------------------------------------------- |
| `GVMR_LOG_LEVEL`  |   `info` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `GVMR_LOG_FORMAT` | `pretty` | Log output format: `pretty` or `json`                |

---

## Example `.env`

```env
# Server
GVMR_PORT=8084

# Paths
GVMR_REPORT_FORMATS_FEED_DIR=/opt/gvm/var_community/lib/gvm/data-objects/gvmd/report-formats
GVMR_WORK_DIR=/tmp/gvmr-lite/work

# Startup
GVMR_REBUILD_ON_START=true

# Request limits
GVMR_MAX_BODY_BYTES=52428800

# Auth (none|api_key|jwt)
GVMR_AUTH_MODE=jwt

# API key mode
# GVMR_API_KEY=supersecret
# GVMR_API_KEY_HEADER=X-API-Key

# JWT mode
GVMR_JWT_SECRET=supersecret_shared_between_services
GVMR_JWT_AUDIENCE=gvmr-lite
GVMR_JWT_ISSUER=gvmd-lite
GVMR_JWT_CLOCK_SKEW_SECONDS=300
GVMR_REQUIRED_SCOPE_RENDER=render
GVMR_REQUIRED_SCOPE_SYNC=sync

# Logging
GVMR_LOG_LEVEL=debug
GVMR_LOG_FORMAT=pretty
```

---

## Notes

- Unknown environment variables are ignored.
- Values loaded from environment variables override defaults.
- A local `.env` file can be used during development.
- Some variables may be documented before their full implementation is completed in the Rust service. In such cases, the documented values describe the intended compatibility target.

---
