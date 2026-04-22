# gvmr-lite-rs

A lightweight Rust REST service for parsing, caching, and rendering GVM report formats.

This project is a Rust rewrite of `gvmr-lite`, focusing on:
- preserving external API behavior
- improving modularity and maintainability
- preparing for better performance and rendering backends

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
````

With environment variables:

```bash
GVMR_PORT=8084 GVMR_LOG_LEVEL=debug cargo run
```

Or using a `.env` file:

```bash
cargo run
```

---

## API

### Health endpoints

```bash
curl http://localhost:8084/health/live
curl http://localhost:8084/health/ready
```

---

## Project Structure

```text
src/
  api/        # HTTP handlers + DTOs
  app/        # Router + AppState
  config/     # Settings loading
  telemetry/  # Logging setup
  main.rs     # Entry point
```

---

## Design Principles

* Clear separation of concerns (API, service, domain, infra)
* Typed configuration via environment variables
* Minimal framework leakage into core logic
* Pluggable rendering architecture (planned)

---

## Roadmap

* [ ] Format cache service
* [ ] Authentication (api_key, jwt)
* [ ] Report format sync
* [ ] Rendering pipeline
* [ ] OpenAPI / Swagger
* [ ] Integration tests

---

## License

MIT

---
