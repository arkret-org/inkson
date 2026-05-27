# yougen — Observability

> Crash + structured-trace pipeline for yougen. Everything below is
> **opt-in**: nothing leaves the device until the user flips the
> telemetry toggle and the build is configured.

## 1. Structured tracing (`tracing-subscriber`)

yougen uses the `tracing` crate workspace-wide. The default subscriber
is installed in `main.rs` for native targets and via the wasm
console-bridge subscriber on the web build.

To raise verbosity in a dev session:

| Target | How |
| --- | --- |
| Native | `RUST_LOG=yougen=debug,contrix=info cargo run` |
| Web | DevTools → Console; pass `?log=debug` if your dev server honours it. |

Log line fields you can rely on:

- `actor` — the local DID (never a third-party identity).
- `action` — verbose dotted name (`oidc.refresh`, `mls.commit`,
  `push.subscribe`).
- `outcome` — `success` / `error` / `denied`.
- `request_id` — soland's `x-contrix-request-id` for every HTTP exchange
  the line refers to (P5 addition; see §3 below).
- `note` — optional free-form context.

The line format mirrors sodmin's `format_admin_audit_line` so operator
tools can ingest yougen output without schema work.

## 2. Sentry opt-in

`crate::telemetry::sentry_init` is the only place Sentry is touched.
The init is gated on **both** of the following:

1. `CrashTelemetryPrefs::enabled == true`. The user must flip the
   toggle in **Settings → Privacy → Crash telemetry**. The
   `CrashTelemetryToggle` component writes the preference into
   `LocalStateStore`. Default is `false`.
2. The build-time `SENTRY_DSN` environment variable is non-empty.
   When unset, the init function logs a debug breadcrumb and returns
   `None`. No panic, no payload, no network call.

If both conditions hold the init returns a Sentry guard that lives for
the rest of the process. Drop the guard (sign out / process exit) to
flush + close the transport.

On wasm builds the `sentry` crate is **not** compiled in at all. Crash
capture for the web target depends on the browser's reporting hooks
(`window.onerror`, `unhandledrejection`) which `report_problem.rs`
collects on demand when the user submits a bug.

### Turning it on (developer)

```powershell
$env:SENTRY_DSN = "https://<key>@<org>.ingest.sentry.io/<project>"
cargo build --release
./target/release/yougen
```

Then in the running app: **Settings → Privacy → Crash telemetry → On**.

### Turning it off

Flip the toggle. The Sentry guard is dropped immediately and the
in-flight transport flushes. No further events leave the device until
the toggle is flipped again.

## 3. `request_id` propagation (P5)

Every yougen → soland HTTP call sets the `x-contrix-request-id` header.
soland echoes the value in:

- Success response bodies (when applicable).
- Every error envelope (`ErrorEnvelope.request_id`).
- Server-side log lines.

The P5 work threads the same value end-to-end on the client:

1. `crate::api` stores the inbound `x-contrix-request-id` on every
   response.
2. `tracing` log lines emitted during the call carry the value via the
   `request_id` field so a `grep` across yougen + soland logs lines up.
3. Error toasts surface a **Copy ID** button so users can paste the ID
   into a bug report. The button is rendered by the global toast
   handler and tagged `data-testid="error-toast-copy-request-id"`.

For bug reports always capture the `request_id` first.

## 4. Local audit log

The `crate::telemetry::emit_user_action_log` path buffers entries into
`LocalStateStore::telemetry_log` (bounded at `TELEMETRY_BUFFER_CAP`).
This is **always-on** and **device-local** — entries never leave the
device unless the user explicitly exports the buffer via
`/developer → Export telemetry log`.

The buffer survives a browser refresh / desktop restart because it rides
on the same `state.json` / `localStorage` channel as the rest of the
local state.

## 5. What we do **not** capture

- Message bodies.
- Recovery material (passphrases, vault blobs, recovery keys).
- Push tokens.
- Cross-signing private keys.
- DPoP private keys.

If you observe any of these in a Sentry payload, file a security issue
(see [`SECURITY.md`](../SECURITY.md)).
