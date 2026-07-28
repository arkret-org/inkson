# Regression Review

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
