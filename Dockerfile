# syntax=docker/dockerfile:1.7
# Build context must contain both `clientx/` and sibling `contrix-rust-sdk/`.
# From the parent directory run:
#   docker build -f clientx/Dockerfile -t clientx-web .

FROM rust:1-bookworm AS build

ARG DIOXUS_CLI_VERSION=0.7.5

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install dioxus-cli --version "${DIOXUS_CLI_VERSION}" --locked

WORKDIR /workspace

COPY contrix-rust-sdk ./contrix-rust-sdk
COPY clientx ./clientx

WORKDIR /workspace/clientx

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/workspace/clientx/target \
    dx build --platform web --release

FROM nginx:1.27-alpine

COPY --from=build /workspace/clientx/target/dx/clientx/release/web/public /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1/ >/dev/null || exit 1
