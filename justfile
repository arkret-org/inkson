# Show available local tasks.
default:
    @just --list

# Start the Dioxus web dev server.
web:
    dx serve --platform web

# Start the Dioxus desktop dev server.
desktop:
    dx serve --platform desktop

# Start the Dioxus mobile dev server.
mobile:
    dx serve --platform mobile

# Run Rust tests.
test:
    cargo test

# Run Playwright e2e tests.
e2e:
    npm run e2e

# Run the local release gate.
release-check:
    npm run release:check
