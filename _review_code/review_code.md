# Regression Review

## 2026-07-29 — Sidecar Chrome/Edge matrix no longer reached the seeded Realm

- Surface: `inkson.strands.kanban.spec.ts` Sidecar browser matrix and its Arkret mock harness.
- Regression: Chrome and Edge both loaded the client shell, but the mocked account/Realm bootstrap
  left the UI at `No Realm tree loaded`; the executed Sidecar cases then timed out waiting for the
  seeded Kanban card, and the full matrix could not finish.
- Detection: Sidecar completion-gate verification against the real WASM bundle on Chrome and Edge.
- Resolution: the mock account subscribe and Realm bootstrap fixtures now emit the current
  accepted frame shape, expose a stable reload bootstrap, and fail fast when the seeded Realm tree
  is absent. The matrix also covers explicit publish cancel/confirm, immutable retry payloads,
  source-route and draft preservation, long-history dedupe, scroll restoration, multi-Agent
  addressing, narrow layout, and pending-access fail-closed behavior.
- Verification: the stable joint-e2e WASM bundle passed all eight Sidecar cases in installed Chrome
  and Edge twice. The request-count assertion proves mode/track changes do not replay the source
  Realm history, and each case runs with trace capture enabled.
- Prevention dimension: E2E bootstrap helpers must fail early on missing seeded Realm state instead
  of letting every product assertion consume the full test timeout.
- Status: resolved.

## 2026-07-29 — the Playwright dev-server port was not configurable

- Surface: `playwright.config.ts` local web-server startup.
- Regression: the base URL could be overridden, but `dx serve` always bound port 4727. A system
  process reserving that port made the browser gate impossible to start.
- Detection: Sidecar Chrome/Edge completion-gate verification.
- Resolution: derive the Dioxus server port from the configured E2E URL and add
  `INKSON_E2E_PORT` for collision-free local startup.
- Prevention dimension: the readiness probe URL and spawned server must share one source of truth.
- Status: resolved.

## 2026-07-29 — browser leader gate did not compile for WASM

- Surface: `app::web_leader` Web Lock acquisition and storage-lease renewal.
- Regression: the Web Lock callback parameter was not explicit enough for the WASM closure
  conversion, and the nested browser module did not import `WritableExt` for `Signal::set`.
- Detection: the isolated federated cotest environment failed while building the real Inkson
  browser bundle.
- Resolution: type the callback input as `JsValue` and import the signal write extension in the
  module that performs lease state transitions.
- Prevention dimension: browser-only coordination paths must be compiled as part of the joint
  end-to-end preparation gate, even when native test targets do not exercise them.
- Status: resolved; verified by the joint-e2e web build.

## 2026-07-28 — recovery receipt retry did not preserve its idempotency identity

- Surface: `record_completed_recovery_receipt` and device recovery partial retry.
- Regression: every retry mints a new `receipt_id` and `completed_at`, while the durable recovery
  checkpoint does not preserve the first signed receipt. A response-lost retry therefore submits
  different bytes for the same recovery session, and the UI discards the concrete receipt error.
- Detection: end-to-end recovery flow review after the live run stopped before the receipt handler.
- Required correction: construct and persist the public signed receipt before its first submit,
  replay byte-identical wire bytes after uncertain outcomes, and surface a non-secret diagnostic
  while keeping the session in a resumable partial state.
- Prevention dimension: retry-safe protocol writes need a fixed client-side operation identity
  before the first network side effect.
- Status: the direct receipt submit and client-authored recovery checkpoint path have been removed;
  the merged P0 contract assigns replacement work to
  `RecoveryTransaction.issue_terminal_receipt`.

## 2026-07-28 — raw Recovery Key input buffer was cleared without zeroization

- Surface: `DeviceAuthorizationPrompt`.
- Regression: the normalized async copy uses `Zeroizing<String>`, but the form signal that holds
  the user-entered 24 words is a normal `String`; replacing it with `String::new()` releases the
  allocation without overwriting its contents.
- Detection: secret-lifetime scan of all added recovery UI lines.
- Required correction: hold the Rust-side input buffer in a zeroizing owner, zeroize on every
  transition/cancel/unmount path, and continue documenting that browser DOM/runtime copies cannot
  be absolutely erased.
- Prevention dimension: password/recovery-secret widgets must use a zeroizing application buffer
  from the first keystroke, not only after normalization.
- Status: the affected direct-saga UI has been removed. The transaction-based replacement must
  satisfy this requirement before reintroducing the 24-word form.

## 2026-07-28 — exporter-AEAD history fallback scanned keys across declared epochs

- Severity: P0 confidentiality/integrity boundary.
- Status: resolved and covered by focused round-trip tests.
- Evidence: the old tier-3 decrypt path reconstructed a separate raw JSON AAD
  and, when the payload's declared epoch had no matching key, scanned every
  granted history secret until one opened the ciphertext. The current SDK
  instead binds typed `EncryptedEnvelopeAad`, `KeyRefObject`, epoch, purpose
  and negotiated suite in one closed immutable header.
- Resolution: Inkson now authors through
  `encrypt_payload_exporter_aead`, accepts only the payload's exact canonical
  exporter key reference and Realm AAD, verifies the payload digest, and looks
  up only `history_secret[payload.epoch]`. Missing or inconsistent metadata
  fails closed; there is no cross-epoch recovery scan.
- Prevention dimension: authenticated immutable-header members are protocol
  claims, not hints. A receiver must never search alternate keys to compensate
  for a signed epoch or key-reference mismatch.

## 2026-07-29 — Sidecar fold used Event ids as canonical digest stand-ins

- Severity: P0 durable-truth determinism boundary.
- Status: resolved and covered by focused Sidecar refold tests.
- Evidence: accepted request and control facts copied `event_id` into `event_digest`; a successful
  submit also seeded a delivered cache before the complete accepted Event Envelope had synced back.
  Same-sequence siblings could therefore select a different winner than the canonical digest rule.
- Resolution: submission now persists only the accepted Event identity. The fact remains non-fold
  until the complete accepted Envelope can recompute `Event::event_digest()`; request/control
  Envelope digest failure is fail-closed, and legacy stored facts are upgraded on syncback.
- Prevention dimension: identifiers never substitute for canonical content digests. Any fold field
  derived from an accepted Envelope must remain unavailable until that Envelope is locally verified.

## 2026-07-30 — duplicate proposal receipt authoring bypassed the SDK canonical signer

- Severity: P2 protocol-authoring drift risk.
- Status: resolved; covered by SDK receipt authoring tests and the live onboarding gate.
- Evidence: while tracing a separate frontier policy-validation failure, `event_submit` and
  `fresh_device_recovery` were found to manually rebuild member timestamps, digest and detached JWS
  even though `authorization_lease` already used the SDK
  `ProposalMemberReceipt::issue_with_signer` path.
- Resolution: both duplicate implementations now use the SDK helper with the authenticated
  principal-bound signer adapter and assemble the aggregate through
  `ControlProposalReceipt::from_member_receipts`.
- Prevention dimension: canonical signed protocol artifacts must have one SDK authoring primitive;
  product clients choose authority context and signer but do not copy transcript construction.
