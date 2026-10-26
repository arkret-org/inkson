# syntax=docker/dockerfile:1.7
# The context contains sibling application/SDK trees. UI dependencies use Cargo.lock Git sources.
FROM rust:bookworm AS build
ARG WASM_BINDGEN_VERSION=0.2.129
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32-unknown-unknown
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/usr/local/cargo/git cargo install wasm-bindgen-cli --version "${WASM_BINDGEN_VERSION}" --locked
WORKDIR /workspace
COPY arkret-rust-sdk ./arkret-rust-sdk
COPY arkret-spec ./arkret-spec
COPY garth ./garth
COPY chime ./chime
COPY inkson ./inkson
WORKDIR /workspace/inkson
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/usr/local/cargo/git --mount=type=cache,target=/workspace/inkson/target python3 scripts/build_web.py --release --out-dir /web-public
FROM nginx:1.31-alpine
COPY --from=build /web-public /usr/share/nginx/html
COPY --from=build /workspace/inkson/docker/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD wget -qO- http://127.0.0.1/ >/dev/null || exit 1
