default:
    @just --list

check:
    cargo check --all-targets

test:
    cargo test --all-targets

lint:
    cargo fmt --all -- --check
    cargo clippy --all-targets -- -D warnings

web-check:
    cargo check --target wasm32-unknown-unknown

desktop:
    cargo run
