# gvmr-lite-rs

A lightweight Rust REST service for parsing, caching, and rendering GVM report formats.

This project is a Rust rewrite of `gvmr-lite`, focusing on:

- preserving external API behavior
- improving modularity and maintainability
- preparing for better performance and rendering backends

---

## Documentation

- [Environment Variables](./docs/ENVIRONMENT_VARIABLES.md)

---

## Status

Early development (bootstrap phase)

Currently implemented:

- Typed configuration (`GVMR_*`)
- Structured logging (tracing)
- Basic app wiring (Axum)
- Health endpoints:
  - `/health/live`
  - `/health/ready`

---

## Running locally

### Requirements

- Rust (stable)
- Cargo

### Run

```bash
cargo run
```

With environment variables:

```bash
GVMR_PORT=8084 GVMR_LOG_LEVEL=debug cargo run
```

Or using a `.env` file:

```bash
cargo run
```

---

## Development Setup

### Recommended Tools

Install these tools for a faster and more productive development workflow:

```bash
cargo install bacon
cargo install cargo-nextest --locked
cargo install cargo-tarpaulin
```

### Usage

Start the development watcher:

```bash
bacon
```

Useful shortcuts inside Bacon:

| Key | Action                   |
| --- | ------------------------ |
| `r` | Run the service          |
| `t` | Run tests (nextest)      |
| `c` | Run clippy (strict)      |
| `f` | Fix formatting           |
| `x` | Check formatting         |
| `v` | Run coverage (tarpaulin) |

---

## Code Quality

### Format code

```bash
cargo fmt --all
```

### Lint (strict)

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

### Run tests

```bash
cargo nextest run --all-targets
```

### Coverage

```bash
cargo tarpaulin --all-targets --ignore-tests --out Html
```

---

## API

When the service is running, interactive API documentation is available:

- Swagger UI: [http://localhost:8084/docs](http://localhost:8084/docs)
- OpenAPI spec: [http://localhost:8084/api-docs/openapi.json](http://localhost:8084/api-docs/openapi.json)

---

## Design Principles

- Clear separation of concerns (API, service, domain, infra)
- Typed configuration via environment variables
- Minimal framework leakage into core logic
- Pluggable rendering architecture (planned)

---

## License

MIT

---
