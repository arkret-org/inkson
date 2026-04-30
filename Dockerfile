# syntax=docker/dockerfile:1.7
# Build context must contain both `yougen/` and sibling `contrix-rust-sdk/`.
# From the parent directory run:
#   docker build -f yougen/Dockerfile -t yougen-web .

FROM rust:1-bookworm AS build

ARG DIOXUS_CLI_VERSION=0.7.5

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install dioxus-cli --version "${DIOXUS_CLI_VERSION}" --locked

WORKDIR /workspace

COPY contrix-rust-sdk ./contrix-rust-sdk
COPY yougen ./yougen

WORKDIR /workspace/yougen

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/workspace/yougen/target \
    dx build --platform web --release

FROM nginx:1.29-alpine

COPY --from=build /workspace/yougen/target/dx/yougen/release/web/public /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1/ >/dev/null || exit 1
