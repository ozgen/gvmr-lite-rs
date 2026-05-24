FROM rust:1.88-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install typst-cli --version 0.14.0 --locked

COPY Cargo.toml Cargo.lock ./
COPY crates/gvmr-core/Cargo.toml crates/gvmr-core/Cargo.toml
COPY crates/gvmr-server/Cargo.toml crates/gvmr-server/Cargo.toml
COPY crates/gvmr-cli/Cargo.toml crates/gvmr-cli/Cargo.toml

COPY crates crates

RUN cargo build --release -p gvmr-server --bin gvmr-server


FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    xsltproc \
    xmlstarlet \
    graphviz \
    libcairo2 \
    texlive-latex-base \
    texlive-latex-recommended \
    texlive-fonts-recommended \
    texlive-pictures \
    texlive-latex-extra \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 10001 gvmr \
    && mkdir -p /tmp/gvmr-lite/work \
    && chown -R gvmr:gvmr /tmp/gvmr-lite

WORKDIR /app

COPY --from=builder /app/target/release/gvmr-server /usr/local/bin/gvmr-server
COPY --from=builder /usr/local/cargo/bin/typst /usr/local/bin/typst
COPY templates /app/templates

USER gvmr

EXPOSE 8084

ENTRYPOINT ["/usr/local/bin/gvmr-server"]