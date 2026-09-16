# gvmr-lite-rs

A lightweight Rust REST service for parsing, caching, and rendering GVM report formats.

This project is a Rust rewrite of `gvmr-lite`, focusing on:

- preserving external API behavior
- improving modularity and maintainability
- preparing for better performance and rendering backends

---

## Build status

![CI](https://github.com/ozgen/gvmr-lite-rs/actions/workflows/ci.yml/badge.svg)
![Lint](https://github.com/ozgen/gvmr-lite-rs/actions/workflows/lint.yml/badge.svg)
![Format](https://github.com/ozgen/gvmr-lite-rs/actions/workflows/fmt.yml/badge.svg)
[![codecov](https://codecov.io/gh/ozgen/gvmr-lite-rs/branch/main/graph/badge.svg)](https://codecov.io/gh/ozgen/gvmr-lite-rs)

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
- Make

### Run the server

```bash
make run-server
```

With environment variables:

```bash
GVMR_PORT=8084 LOG_LEVEL=debug make run-server
```

Or using a `.env` file:

```bash
make run-server
```

### Run the CLI

By default, the CLI target shows help:

```bash
make run-cli
```

Pass CLI arguments with `CLI_ARGS`:

```bash
make run-cli CLI_ARGS="--xml scripts/report.xml --type native --output report.pdf"
```

---

## Development Setup

### Recommended Tools

The Makefile is the main local development entry point.

Install the optional Cargo tools used by the test and coverage targets:

```bash
cargo install cargo-nextest --locked
cargo install cargo-llvm-cov
```

### Available Make targets

Show all common commands:

```bash
make help
```

Check the whole workspace:

```bash
make check
```

Check individual crates:

```bash
make check-core
make check-server
make check-cli
```

Run the server:

```bash
make run-server
```

Run the CLI:

```bash
make run-cli
```

Run the standard workspace test suite:

```bash
make test
```

Run tests with `cargo-nextest`:

```bash
make nextest
```

Generate and open HTML coverage:

```bash
make cover
```

Run strict Clippy checks:

```bash
make clippy
```

Format the workspace:

```bash
make fmt
```

Check formatting without modifying files:

```bash
make fmt-check
```

Build the workspace:

```bash
make build
```

Build release binaries:

```bash
make build-release
```

Clean build artifacts:

```bash
make clean
```

---

## Code Quality

The preferred workflow is to use the Makefile so local development and CI can share the same commands.

### Format code

```bash
make fmt
```

### Check formatting

```bash
make fmt-check
```

### Lint (strict)

```bash
make clippy
```

### Run tests

```bash
make test
```

For `cargo-nextest`:

```bash
make nextest
```

### Coverage

```bash
make cover
```

### Full local verification

A typical pre-commit or pre-push verification sequence is:

```bash
make fmt-check
make clippy
make test
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
