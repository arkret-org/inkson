$ErrorActionPreference = "Stop"

Push-Location (Join-Path $PSScriptRoot "..")
try {
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings
    cargo test
    python scripts/build_web.py
    npm install
    npm run e2e
}
finally {
    Pop-Location
}
