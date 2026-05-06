# Security policy

## Reporting a vulnerability

Please **do not open a public GitHub issue** for security vulnerabilities.

Email the maintainers at `chris@acroidea.com` with:

- A description of the issue and its impact.
- Steps to reproduce, including any proof-of-concept payload.
- Affected commit / tag / build (e.g. `cargo run --version` output, web build hash).
- Whether you would like credit in the public advisory.

We will acknowledge receipt within five business days and provide a status
update within ten. Coordinated disclosure timelines depend on severity; we
aim to ship a fix within 30 days for critical issues.

## Scope

In scope:

- The yougen client binary (desktop, mobile) and the Dioxus web build.
- The Rust crate published from this repository.
- The `Dockerfile` and CI workflows under `.github/workflows`.

Out of scope (report upstream instead):

- The Contrix protocol itself — see `contrix-spec`.
- The `contrix-rust-sdk` crate — see that repository.
- The reference server (`soland`) — see that repository.
- The push gateway (`chime` / `chask`).
- Third-party dependencies; we will assist in coordinating fixes upstream.

## Threat model assumptions

- The web build runs untrusted JavaScript on the same origin as user data.
  Private preferences (locale, theme, etc.) are sealed with
  ChaCha20-Poly1305 keyed off the account DID before being written to
  `localStorage`; legacy XOR-obfuscated values written by older builds are
  still readable for one upgrade cycle. **Session tokens, sync cursors,
  raw operations, and projection caches are stored plaintext** and remain
  readable by any script on that origin. Production deployments must
  serve the web build over HTTPS only and lock down third-party scripts.
- Desktop / mobile builds persist the same fields under the OS app-data
  directory. File permissions follow the platform default; treat the
  config file as user-private.
- The `CLIENTX_SESSION_TOKEN` env var is provided as a convenience for CI
  bootstrap. Do not commit it; prefer short-lived dev-login tokens. See
  `views/settings.rs` for the in-app warning that mirrors this guidance.

## Hardening checklist for self-hosted deployments

- Set `CLIENTX_SERVER_URL` to an HTTPS origin; the client refuses
  non-loopback HTTP at config validation.
- Configure CORS on `soland` to allow only the origins serving your web
  build.
- Pin Docker image tags by digest in production; the `:main` tag rolls
  forward.
- Subscribe to release notifications so you can patch the binary within
  the disclosure window.
