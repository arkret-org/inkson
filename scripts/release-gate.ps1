$ErrorActionPreference = "Stop"

Push-Location (Join-Path $PSScriptRoot "..")
try {
    . (Join-Path $PSScriptRoot "lib/cargo.ps1")
    $null = Get-CargoTargetDirectory -RepositoryRoot (Get-Location).Path
    cargo +nightly fmt -p inkson -- --check
    cargo clippy --locked --features app --all-targets -- -D warnings
    cargo test --locked --features app
    python scripts/build_web.py
    npm ci
    npm run e2e
}
finally {
    Pop-Location
}
