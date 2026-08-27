# syntax=docker/dockerfile:1.7
# Build context must contain `inkson/` and all of its sibling path dependencies.
# `yoface` is NOT among them: it is a private cargo git dependency, so the
# build fetches it from github.com/arkret-org/yoface and needs a GitHub token
# with read access, mounted as the `github_token` build secret.
# From the parent directory run:
#   GITHUB_TOKEN=<pat> docker build -f inkson/Dockerfile \
#     --secret id=github_token,env=GITHUB_TOKEN -t inkson-web .

FROM rust:bookworm AS build

ARG DIOXUS_CLI_VERSION=0.7.9

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install dioxus-cli --version "${DIOXUS_CLI_VERSION}" --locked

WORKDIR /workspace

COPY arkret-rust-sdk ./arkret-rust-sdk
COPY garth ./garth
COPY chime ./chime
COPY inkson ./inkson

WORKDIR /workspace/inkson

# `inkson/.cargo/config.toml` sets `net.git-fetch-with-cli`, so cargo fetches
# the private `yoface` dependency through git and asks this credential helper
# for the token. The helper reads the secret at call time, so the token lives
# only in the tmpfs mount for the duration of this layer — it never lands in
# the build cache or the image.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/workspace/inkson/target \
    --mount=type=secret,id=github_token,required=true \
    git config --global credential.helper \
        '!f() { echo username=x-access-token; echo "password=$(cat /run/secrets/github_token)"; }; f' && \
    dx build --platform web --release

FROM nginx:1.29-alpine

COPY --from=build /workspace/inkson/target/dx/inkson/release/web/public /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1/ >/dev/null || exit 1
