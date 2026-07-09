# syntax=docker/dockerfile:1.7
# Build context must contain `inkson/`, sibling `arkret-rust-sdk/`, and sibling `chime/`.
# From the parent directory run:
#   docker build -f inkson/Dockerfile -t inkson-web .

FROM rust:1-bookworm AS build

ARG DIOXUS_CLI_VERSION=0.7.5

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install dioxus-cli --version "${DIOXUS_CLI_VERSION}" --locked

WORKDIR /workspace

COPY arkret-rust-sdk ./arkret-rust-sdk
COPY chime ./chime
COPY inkson ./inkson

WORKDIR /workspace/inkson

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/workspace/inkson/target \
    dx build --platform web --release

FROM nginx:1.29-alpine

COPY --from=build /workspace/inkson/target/dx/inkson/release/web/public /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1/ >/dev/null || exit 1
