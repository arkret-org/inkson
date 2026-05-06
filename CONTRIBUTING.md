# Contributing to yougen

Thanks for considering a contribution. yougen is the cross-platform Contrix
client; it ships alongside `contrix-rust-sdk` and `chime` as sibling path
dependencies.

## Local setup

Clone the three repositories side by side:

```
parent/
├── yougen/
├── contrix-rust-sdk/
└── chime/
```

Install the Rust toolchain (1.95+ as of `Cargo.lock`), then:

```powershell
cargo check --all-targets
cargo test
```

For the web shell:

```powershell
cargo install dioxus-cli --version 0.7.5 --locked
dx serve --platform web
```

For end-to-end browser tests (Playwright with mocked `/api/v1/*`):

```powershell
npm install
npm run e2e
```

The release gate (matches the GitHub Actions `CI` job) runs locally:

```powershell
npm run release:check
```

## Branching and commits

- Cut feature branches from `main`.
- Keep commits small and reviewable. Reference the relevant `_todos.md`
  task ID (e.g. `T20`, `R03`) in the subject.
- Run `cargo fmt` and `cargo clippy --all-targets -- -D warnings` before
  pushing — CI fails the build on either of these.
- Add or update tests for behaviour changes. The `cargo test` suite
  includes drift-detection vectors against the spec registry.

## Pull requests

- Fill in `.github/PULL_REQUEST_TEMPLATE.md`. Link the spec sections you
  align with and any companion PRs in `contrix-rust-sdk` or `soland`.
- Keep the diff focused. Refactors and feature changes belong in
  separate PRs.
- A reviewer will sign off once CI is green and the spec alignment
  checklist is satisfied.

## Specification alignment

yougen tracks `contrix-spec` closely. When the spec moves, prefer:

1. Updating `src/conformance.rs` and the relevant view to surface the new
   event kind / object; ship the smallest UI scaffold first.
2. Filing a follow-up task in `_todos.md` for any reducer / SDK work.

`event-kind-registry.json` is the canonical source. Do not invent local
event kinds.

## Reporting bugs and security issues

- Functional bugs: open a GitHub issue using the bug-report template.
- Vulnerabilities: see `SECURITY.md` — do not file a public issue.
