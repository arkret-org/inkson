# Yougen Changelog

All notable yougen changes are recorded here. Yougen is the Dioxus
cross-platform Cokret v1 reference client (macOS / Windows / Linux / iOS /
Android / web).

## R3.4 — Spec sync 2026-05-31 (cokret-spec @ c2848a4)

- Synced protocol-facing names and fixtures to `c2848a4`: event envelope schema naming, `_ids` grant constraints, accountability principal vocabulary, `ck:rtc_participant:` media participants, agent session start fields, and key-backup signature algorithm naming where applicable.

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.

## R3.3 — Spec sync 2026-05-28 (cokret-spec @ cced4b8)

- CXP-0011: client-side shareable object links. New `src/object_address.rs`
  wraps the SDK addressing grammar (`parse_address` / `build_address` /
  `build_https_landing` / `target_digest`) into a typed `ShareTarget`
  (Realm / Flow / Message) that builds both link forms — the default
  HTTPS-fragment landing link (target + token live in the `#` fragment, never
  reaching the landing host) and the `web+cokret:` "open in app" form — plus
  `OpenedLink` which parses either form, fails closed on bad grammar, and routes
  to the local UI by `target_kind` (Realm → Space page, Flow → flow timeline,
  Message → message anchor).
- New `CokretApi::directory_resolve_target` wraps `cx.directory.resolve_target`
  (mirrors `resolve_realm`); the directory view gains a minimal "Open shared
  link" entry point that resolves a pasted link and navigates on success. All
  resolve failures collapse to one friendly "link unavailable or expired"
  message (never distinguishes not_found vs unauthorized — anti-enumeration).
- Invite-token target binding: `ShareTarget::invite_target_digest` computes the
  `target_digest` an invite token would bind (fails closed on alias realms). The
  parse path lifts a `tok=` out of `lt=invite` links for the resolve request.
  Web protocol-handler registration ships the **HTTPS-fragment-only** path by
  default; `web_protocol_handler_template` enforces a fragment-only `%s`
  substitution for opt-in `registerProtocolHandler` callers so the substituted
  URI never leaks to the landing host.
- i18n: `object_link.*` share / open-link strings (Chinese-first + English).
- Deeper UI (per-object context-menu Share actions, invite-token issuance,
  confirm-before-navigate preview card) and native OS deep-link registration
  (Info.plist / AndroidManifest / `.desktop` / Windows registry) deferred
  `TODO(R3.3.1)`.

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.

## R3.2 — Spec sync 2026-05-28 (cokret-spec @ b56cab1)

- Dropped `MemberIdentity.primary_handle`/`handles[]`; roster `identity_state_digest` → `member_display_state_digest`; payload digest → `identity_payload_digest`.
- Mention shape v2: `subject_id` authoritative; `handle_at_time`/`display_name_at_time`/`mention_text_original` audit-only. Render path uses the SDK `render_mention` helper with `MentionRender` fallback tiers (verified/cached/name-only/unresolved CSS).
- New `list_handles_for_subject` API call + "Why am I seeing this handle?" panel; handle settings now point users to the org issuer flow (yougen never sets handles via profile/member-identity).
- Live claim-set snapshot plumbing + DID metadata as_of resolution deferred `TODO(R3.2.1)`.

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.
## R3 — Spec sync 2026-05-27 (cokret-spec @ b47ff6ec)

- CALL-1 / CALL-2: RTC token acquisition wires the chime / SDK `cx.call.media.token_exchange` helper in `src/media/rtc.rs`; `focus_unavailable_for_client` surfaced as a retry / leave-call toast in `src/views/call.rs` with no silent focus fallback.
- MEDIA-1..3: documented SFrame-key derivation from MLS-Exporter `cx-rtc-frame-key/v1` (rejects backend-supplied keys with `e2ee_key_source_unauthorised`); ParticipantConnected cross-check against `cx.call.state.participants[]` (`participant_identity_unrecognised`); recording-artifact pipeline rejects non-Cokret Egress destinations (`recording_artifact_pipeline_bypassed`). Renderer enforcement stubbed for R3.1.
- AGENT-1..3: HTTP path switched `/revoke` → `/deactivate`; agent list renders `paused` / `deactivated` states with Resume / Provision affordances and a default-hide-deactivated filter (`src/views/agents.rs`); localized en + zh toasts for `pairing_request_expired`, `proof_invalid`, `agent_paused`, `agent_deactivated`.
- HDL-1 / CURSOR-1 / SEL-1: new `src/identity_handle.rs` plus onboarding inline NFC + script-mixed warnings and friendly `handle_homograph_forbidden` copy; cursors treated as fully opaque in the network layer; circle UI uses `ck:circle:<uuid>` selector kind for grant pages.
- REC-1: recovery stub view (`src/views/recovery.rs`) renders policy detail (proof_kind enum, threshold), receipt history with `proof_summary[]`, and surfaces `recovery_witness_revoke_lagging` / `recovery_policy_mismatch` / `challenge_proof_invalid`.

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.

## [Unreleased]

### Circle rollout (CXP-0007 + cross-stack P3B)

- **Added** Circle UX surface: Space-sidebar Circle list, Flow/Space scope
  picker, composer banner labelling Circle-scoped writes, timeline accent
  rail + tooltip on Circle-scoped messages, dedicated `views/circle.rs`
  Circle-detail view, create-Circle modal in Realm detail page,
  `Relation::ConfidentialDiscussionOf` cross-link banner above linked
  Flows, and `sync_engine` envelope routing that selects the right MLS
  group from each event's `effective_scope`. Chime push subscriptions now
  pass the active Circle id so `PushNotification.circle_id` filtering and
  per-Circle mute prefs flow through end-to-end.
- **Added** CXP-0007 error-code UI surface: 5 reason codes
  (`circle_realm_mismatch`, `circle_not_active`,
  `circle_member_must_be_realm_member`, `scope_rebind_forbidden`,
  `metadata_encryption_floor_violation`) + the top-level
  `delivery_binding_handed_over` code now render as user-facing toasts
  with English i18n strings.
- **Added** multi-account profile switching: `ClientConfig` now holds a
  `Vec<AccountProfile>` keyed by `active_profile_id`, with an avatar
  dropdown switcher; `sync_engine` swaps cursor / token / push
  registration on switch.
- **Added** offline queue is now the canonical write path for message
  send, settings write, and push-preference write. A background drain
  worker replays in FIFO with exponential backoff once the network +
  sync anchor are healthy. The UI exposes a "pending N" badge.
- **Added** E2EE `NeedsVerification` badge + Principal / Collaboration
  Realm class badges next to Realm switcher entries.
- **Added** desktop bundling DRY-RUN scripts for macOS (.app via
  `cargo-bundle` / `dx bundle`), Windows (.msi via `cargo-wix`), and
  Linux (AppImage + .deb). All local-only — nothing is uploaded; the
  signing path uses a placeholder identity that is rejected by real
  notarization.
- **Added** opt-in crash telemetry + in-app "Report a problem" dialog
  that bundles the last 5 minutes of `tracing` lines + app version + OS.
  Telemetry default is OFF.
- **Changed** Floria push URL is now read from the `YOUGEN_FLORIA_URL`
  env var (or `localhost:9001` in dev), with a no-op fallback when prod
  is unset rather than the previous `https://push.example/...` hard-coded
  placeholder.
- **Notes** mobile (iOS / Android) packaging deferred to the next
  milestone; version stays at `0.1.0` and no release artifact ships out
  of this branch.
- **Changed** `api.rs::create_circle` now serialises its wire body
  through the SDK's typed
  [`cokret_sdk::model::CircleDisplay`] / `CircleColorToken` /
  `CircleGlyph` / `CircleDirectoryVisibility` enums instead of a
  hand-rolled `json!` literal, so an invalid color token or glyph
  fails inline instead of being round-tripped through the reducer.
- **Changed** `circle.rs` now re-exports
  [`cokret_sdk::model::EffectiveScope`] directly; the local
  `DecryptedScope` mirror has been deleted. The new
  `classify_scope_match` helper produces `ScopeMatch::{Realm,Circle,
  Mismatch}` for the chat renderer.
- **Changed** `cursor.rs::flow_position_label` accepts an optional
  `last_read_at` and `last_read_at_from_projection` extracts the
  field from the raw account-subscribe Space-position JSON, so the
  label can surface "last read …" until the SDK promotes the field
  onto `SpacePosition` directly.
- **Changed** `config.rs` publishes the typed
  [`ProfileSwitchEvent`] payload and
  `MultiProfileConfig::build_switch_event`; the avatar
  `AccountSwitcher` emits it through a new `on_switch_event` prop
  alongside the legacy `on_switch` string handler.
- **Changed** `SyncEngineContext` now carries
  `Signal<MultiProfileConfig>`; the engine snapshots the active
  `profile_id` at spawn and exits cleanly when the shell rotates
  profiles so the next generation picks up the new cursor / token /
  account_did atomically.
- **Changed** `offline::spawn_offline_drain` now takes a bound
  profile id + shared active-profile RwLock so a profile rotation
  no longer replays the prior profile's queued writes against the
  new account.
- **Changed** `push_registration::RegisterContext` carries an
  optional `active_circle_id`; `build_request` forwards it into the
  chime gateway through the idempotency key and adds the Circle to
  `PushPreferences.muted_circle_ids` so the gateway de-duplicates
  Realm-wide and Circle-scoped wakeups.
- **Removed** the `DEFAULT_PUSH_GATEWAY_FLORIA_NOTIFY` back-compat
  shim in `push.rs`. All call sites now route through
  `push::floria_gateway_url()` directly (env-driven, with a release
  no-op fallback).
- **Added** `views/chat.rs` mounts `CircleComposerBanner` at the
  top of the composer when the active Flow carries a
  `scope_circle_id`. The banner surfaces the Circle title plus the
  visible-member count; Realm-scoped Flows render nothing so the UI
  stays quiet during normal writes.
- **Added** `views/chat.rs` per-message Circle accent rail: each
  message card gets a left-edge coloured ribbon with the Circle
  title as a tooltip when its enclosing Flow has `scope_circle_id`.
- **Added** `chat_message_from_event` now compares the envelope's
  `effective_scope.circle_id` against the payload `scope_circle_id`
  and routes mismatches into
  `MessageCryptoState::NeedsVerification` so the UI badge surfaces
  the disagreement instead of presenting the decrypted body as
  trustworthy.
- **Added** `ConfidentialDiscussionOfBanner` accepts an optional
  `target_space_id` prop that routes the link through
  `Route::TimelineSpace { space_id }` with a `#flow:<id>` anchor.
- **Added** `telemetry::sentry_init` initialises the opt-in Sentry
  client when BOTH the user toggle is on AND the build-time
  `SENTRY_DSN` env var is non-empty. An empty DSN logs a debug
  breadcrumb and returns `None` silently. Wasm builds skip the dep
  entirely. `CrashTelemetryPrefs::load_from_env` honours
  `YOUGEN_CRASH_TELEMETRY_OPT_IN=1|true|on|yes`.

### Testing

- **Changed** `tests/e2e/` is now mock-only. The five `live smoke ...` cases in
  `yougen.flows.spec.ts` and the `YOUGEN_E2E_LIVE*` env-var surface have been
  removed: those scenarios are covered more strictly by the sibling
  [`cotest`](../cotest) joint suite (`cotest/e2e/`), which already boots a real
  `soland` process and drives the yougen UI against it. Yougen's own e2e keeps
  watch over the UI contract (`tests/e2e/mockCokretContract.ts`); end-to-end
  protocol coverage belongs in cotest.

### Round R4 — protocol review closures (2026-05-20, cokret-spec `2a4d39b..a77b995`)

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
  (with `ck:applet:<uuidv7>` accepted for applet IDs).
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

Closes 17 P0/P1 tasks from cokret-spec rounds R2 and R3. Wire-breaking
changes are intentional (aggressive mode); no backward-compat shims.

#### T02 — Broadcast ephemeral signal routing

- New `cokret_sdk::EphemeralEnvelope` wire schema
  (`cx.schema.ephemeral_envelope.v1`) is now the **only** approved network
  path for `cx.call.signal` / `cx.presence` / `cx.typing` /
  `cx.receipt.read`. These four kinds MUST NOT travel via
  `cx.events.submit` any longer (the durable path).
- `CokretApi::submit_ephemeral_envelope` POSTs to
  `/api/v1/ephemeral` with the canonical envelope shape. Enforces the
  5-minute hard ceiling on `expires_at - sent_at` at submit time.
- `CokretApi::submit_to_device_ephemeral` is the equivalent for
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

- Re-export `cokret_sdk::cursor::generate_cursor_handle` (≥22-character
  base64url) and `CURSOR_HANDLE_MIN_LEN` from
  `crate::cursor`. Yougen never hand-rolled `h` values; future callers
  MUST use the SDK helper.

#### T06 — Moderation appeal user flow

- New `views::moderation_appeal` module:
  - `AppealState` projection (None / Submitted / UnderReview / Decided /
    Closed).
  - `build_appeal_submit_op` builds a `cx.moderation.appeal.submit`
    event using `cokret_sdk::AppealSubmitPayload` against
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
  `cokret_sdk::EphemeralEnvelope` / `cokret_sdk::ModerationAppealPayload`
  /  `cokret_sdk::TypedAppealId` /
  `cokret_sdk::EPHEMERAL_ABSOLUTE_HARD_CEILING_MS`.
- Build: `cargo build --message-format short` (Dioxus 0.7.5; SDK
  `cokret` 0.7.0).
