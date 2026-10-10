# syntax=docker/dockerfile:1.7
# Build context must contain `inkson/` and all of its sibling path dependencies.
# Cargo fetches the public `yoface` git dependency from GitHub.
# From the parent directory run:
#   docker build -f inkson/Dockerfile -t inkson-web .

FROM rust:bookworm AS build

ARG DIOXUS_CLI_VERSION=0.7.10

RUN apt-get update && apt-get install -y --no-install-recommends python3 && \
    rm -rf /var/lib/apt/lists/*

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install dioxus-cli --version "${DIOXUS_CLI_VERSION}" --locked

WORKDIR /workspace

COPY arkret-rust-sdk ./arkret-rust-sdk
COPY garth ./garth
COPY chime ./chime
COPY inkson ./inkson

WORKDIR /workspace/inkson

# Cache mounts do not survive into later stages. Copy the completed bundle
# into the image layer before the target cache is unmounted.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/workspace/inkson/target \
    dx build --platform web --release && \
    target_dir="$(cargo metadata --locked --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')" && \
    test -f "$target_dir/dx/inkson/release/web/public/index.html" && \
    cp -a "$target_dir/dx/inkson/release/web/public" /web-public

FROM nginx:1.31-alpine

COPY --from=build /web-public /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1/ >/dev/null || exit 1
