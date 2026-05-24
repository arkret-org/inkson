# Yougen Changelog

All notable yougen changes are recorded here. Yougen is the Dioxus
cross-platform Contrix v1 reference client (macOS / Windows / Linux / iOS /
Android / web).

## [Unreleased]

### Testing

- **Changed** `tests/e2e/` is now mock-only. The five `live smoke ...` cases in
  `yougen.flows.spec.ts` and the `YOUGEN_E2E_LIVE*` env-var surface have been
  removed: those scenarios are covered more strictly by the sibling
  [`cotest`](../cotest) joint suite (`cotest/e2e/`), which already boots a real
  `soland` process and drives the yougen UI against it. Yougen's own e2e keeps
  watch over the UI contract (`tests/e2e/mockContrixContract.ts`); end-to-end
  protocol coverage belongs in cotest.

### Round R4 — protocol review closures (2026-05-20, contrix-spec `2a4d39b..a77b995`)

Closes the round-4 protocol-review commits on the client surfaces. See
[`../_todos.md`](../_todos.md) for the workstream context.

- **BREAKING** `cx.call.signal` v2 — all 13 `signal_type` values supported
  (`offer` / `answer` / `ice` / `hangup` / `reject` / `mute_state` /
  `media_state` / `speaking` / `focus_join` / `focus_leave` / `error` /
  `device_change` / `renegotiate`). Outgoing signals MUST carry `proof`
  (device signature) and a per-`(realm, call, actor, device)` monotonic
  `seq`. Rollback → reject + hangup.
- **BREAKING** `/events/subscribe` consumes typed `EventsSubscribeFrame`;
  `dropped` resumes from the embedded cursor, `resync_required` triggers
  full re-sync, `epoch_rotation` refreshes the session keys.
- **BREAKING** `/events/frontier` for `peer_role=account_client` no longer
  carries `frontier_root` / `signature`; the client no longer depends on
  them.
- **BREAKING** `/blob/presign` now sends `realm_id` for Realm-owned blobs.
- **BREAKING** `/events/submit` chooses `single` or `batch` form; the
  client never emits the `federation` form.
- **Added** invite-claim now produces `subject_proof` (device signature)
  plus the `binding_proof` transcript; the new 5 terminal states render
  in the invite UI.
- **BREAKING** `agent_id` / `applet_id` are constructed strictly as DIDs
  (with `cx:applet:<uuidv7>` accepted for applet IDs).
- **Added** late-recovery banner is now sourced from
  `late_recovery_original_event_id` on
  `cx.audit.policy_access{access_kind=e2ee_late_recovery}`.
- **BREAKING** `ServiceDescribe` consumer enforces 17 required fields;
  `trust_domain` mismatch fails the registration handshake; missing
  `plaintext_visibility` is treated as untrusted.
- **Added** `consent_revoke` UI now shows the required `observed_dots[]`
  list and lets the user revoke them as one action.
- **Added** `SnapshotBootstrap` consumer wires the wire-shape pieces
  (`signature` / `state_digest` / `snapshot_frontier` / `chunks[]`); full
  chunk import is a `TODO(round4)` — failures fall back to full sync.
- **Added** DID method-name regex sweep tightened to
  `^did:[a-z0-9]+:[^\s]+$`.

### Round R2/R3 (2026-05-20) — spec close-out

Closes 17 P0/P1 tasks from contrix-spec rounds R2 and R3. Wire-breaking
changes are intentional (aggressive mode); no backward-compat shims.

#### T02 — Broadcast ephemeral signal routing

- New `contrix_sdk::EphemeralEnvelope` wire schema
  (`cx.schema.ephemeral_envelope.v1`) is now the **only** approved network
  path for `cx.call.signal` / `cx.presence` / `cx.typing` /
  `cx.receipt.read`. These four kinds MUST NOT travel via
  `cx.events.submit` any longer (the durable path).
- `ContrixApi::submit_ephemeral_envelope` POSTs to
  `/api/v1/ephemeral` with the canonical envelope shape. Enforces the
  5-minute hard ceiling on `expires_at - sent_at` at submit time.
- `ContrixApi::submit_to_device_ephemeral` is the equivalent for
  `cx.key.verification.*` (point-to-point form); routes via the existing
  `/device_messages` channel.
- `send_typing` / `send_receipt` (REST shims) now construct an
  `EphemeralEnvelope` first and only fall through to the legacy REST
  endpoint when the dedicated ephemeral channel returns a transport
  error. They never fall back to `cx.events.submit`.
- New envelope builders: `build_typing_envelope`,
  `build_receipt_read_envelope`, `build_presence_envelope`,
  `build_call_signal_envelope`.

#### T03 — Cursor handle generator

- Re-export `contrix_sdk::cursor::generate_cursor_handle` (≥22-character
  base64url) and `CURSOR_HANDLE_MIN_LEN` from
  `crate::cursor`. Yougen never hand-rolled `h` values; future callers
  MUST use the SDK helper.

#### T06 — Moderation appeal user flow

- New `views::moderation_appeal` module:
  - `AppealState` projection (None / Submitted / UnderReview / Decided /
    Closed).
  - `build_appeal_submit_op` builds a `cx.moderation.appeal.submit`
    event using `contrix_sdk::AppealSubmitPayload` against
    `cx.schema.moderation_appeal.v1`. Typed-id binding via
    `TypedAppealId::new`.
  - `AppealEntrypoint` component — "Appeal this moderation decision"
    button + reason textarea; renders near the moderation-report
    surface in `views::timeline`. Submitting POSTs the event via the
    durable `submit_event_envelope` path.
- Status surfaces below the button; the full reviewer surface
  (`*.review` / `*.decision` / `*.close`) is admin scope and a
  follow-up. See `// TODO(round23-T06)` markers.

#### T07 — Realm terminal-state UI

- `LocalStateStore::realm_is_destroyed(realm_id)` projects the local
  `raw_operations` cache for `cx.realm.destroy`. Switches to the SDK
  reducer's typed lifecycle state once that lands —
  `// TODO(round23-T07)`.
- `views::timeline` surfaces a banner ("This realm has been
  permanently retired") and disables the composer + Send button when
  `realm_is_destroyed` is true. Mirrors the server-side
  `realm_terminal_state` rejection.

#### T11 — Presign blob fail-closed UX

- New `api::BlobPresignError` enum (LegalHoldActive, BlobRedacted,
  MediaPlaintextServiceNotAuthorised, NotAuthorised). Classifies the
  4 round-R2/R3 server error codes.
- Each variant carries an `i18n_key()` so the UI surfaces a friendly
  translated message. New i18n strings under `blob.error.*`.
- `views::timeline` blob download path uses `BlobPresignError::from_error`
  on the `Err` arm. No retry, no caching, no logging of the presign
  URL.

#### T15 — OOB code entry validator

- New `recovery_crypto::classify_oob_code` accepts both forms:
  (1) ≥22-char Crockford-base32 (no I/L/0/1/O) for the direct-handle
  form, (2) shorter alphanumeric tokens for the server-resolved lookup
  form.
- New `OobCodeAttemptTracker` implements the 3-strike rule: after the
  third wrong attempt the caller MUST surface a generic
  "code invalid or expired" message (`oob.code.invalid_or_expired`)
  and stop revealing which form failed. i18n string added.

#### T16 — Late key recovery UX

- New top-level module `late_recovery` with `LateRecoveredEvent`
  projection. Computes `lag_minutes()` between original arrival and
  recovery; `banner_text()` renders the user-facing string
  ("Older messages were just decrypted, X minutes after they arrived").
- `should_filter_recovered_event` enforces a defensive client-side
  filter: if the actor was revoked / removed before the recovery
  completed, the recovered content is hidden even if the server
  somehow surfaced it. Mirrors the server's
  `late_recovery_rejected_membership` rejection. New i18n string
  `timeline.late_recovery.banner`.

#### T17 — Consent revoke scope=any UX

- New `views::consent_demo::RevokeAllConsentCard` component. Renders
  the cascade list of all known subscopes (10 entries from
  `CONSENT_REVOKE_CASCADE_SUBSCOPES`) **before** the user can commit,
  and a confirmation modal that re-prints the cascade and demands a
  second click. Builds one `cx.consent.revoke` Move per subscope
  (`// TODO(round23-T17)` to collapse into a single scope=any builder
  once the SDK exposes it).

#### Discussion ref cleanup (round23 spec-prose)

- Confirmed: no residual `discussion_space_ref` references in
  `yougen/src/`. The Realm/Space rework already cleaned up the
  consumer side.

### Internal notes

- All wire payload shapes verified against
  `contrix_sdk::EphemeralEnvelope` / `contrix_sdk::ModerationAppealPayload`
  /  `contrix_sdk::TypedAppealId` /
  `contrix_sdk::EPHEMERAL_ABSOLUTE_HARD_CEILING_MS`.
- Build: `cargo build --message-format short` (Dioxus 0.7.5; SDK
  `contrix` 0.7.0).
