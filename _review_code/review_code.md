# Regression Review

## 2026-08-01 — the typing test asserted a `track_name` the sender no longer emits

- Surface: `signal::tests::typing_body_is_ciphertext_content_not_header_metadata`.
- Regression: `TypingPlaintext.track_name` became optional, with an absent value resolving to
  `discussion` on the receiver, so `SignalPayload::Typing` — which selects no track — stopped
  spelling the default out. The test still asserted the literal `"discussion"` on the wire.
- Detection: `cargo test --lib` during unrelated account-data work. It was invisible for a while
  because the lib **test** target did not compile at all against the current garth API (fixed
  separately by the signal/SDK convergence work), and a lib-only `cargo check` stays green through
  both conditions.
- Resolution: assert `track_name` is absent and state the receiver-side default in the test.
- Prevention dimension: a wire assertion on an optional field with a receiver-side default has to
  say which of the two it is pinning; asserting the resolved value against the emitted body pins
  neither.
- Status: resolved.

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
- Evidence: while tracing separate live-gate failures, `event_submit` and
  `fresh_device_recovery` were found to manually rebuild member timestamps, digest and detached JWS
  even though `authorization_lease` already used the SDK
  `ProposalMemberReceipt::issue_with_signer` path. A later pairing run exposed a third
  `EventSubmitter::prepare_initial_submissions` path that still bypassed the corrected authority
  router, hashed `NotaryValue::single_did(actor)` and signed as the managed Agent rather than its
  controller.
- Resolution: `fresh_device_recovery` uses the SDK helper, while every normal initial publication
  now passes through `authorization_lease::standard_initial_submission`; the stale local receipt
  author and the SDK callback detour were deleted. The one publication wrapper selects the exact
  authority value and principal-bound signer, then assembles the aggregate through the SDK/wire
  receipt constructors.
- Prevention dimension: canonical signed protocol artifacts must have one SDK authoring primitive;
  product clients choose authority context and signer but do not copy transcript construction.

## 2026-07-30 — visible Realm previews incorrectly suppressed pending invite notifications

- Severity: P1 functional regression.
- Status: resolved in both the background reducer and UI hydration paths; covered by focused
  notification projection tests. The full live joint gate is rerun as a separate integration
  verification before task closure.
- Evidence: an invitee's account snapshot contained the target Realm with
  `members[].membership = invite`, but `joined_realm_ids` classified every
  `realm_projections` key as joined. The refresh path then removed the pending
  invite even though `/_arkret/self/authz/invites` returned it.
- Resolution: the shared invite-suppression rule now requires a typed roster
  entry for the current actor whose membership is exactly `join`. Both
  canonical account frames and cached local projections consume the same rule;
  discoverable previews and `invite`/`knock` states remain visible to the
  notification fold.
- Prevention dimension: projection visibility is not authorization or
  membership. UI gates must consume the typed membership state rather than
  infer it from object presence.

## 2026-07-30 — managed Agent PCR control writes asked the Principal Server for proposal receipts

- Severity: P1 provisioning blocker.
- Status: resolved in the publication-wrapper routing path; covered by the delegated-PCR
  authority unit test. The full live Agent gate is rerun before task closure.
- Evidence: Agent allocation and managed-PCR genesis succeeded, but the first `ak.mls.genesis`
  durable attempt called `/_arkret/self/control-proposal-receipts`; Soland correctly returned
  `policy_violation: this service is not a current proposal authority`, leaving the Event queued
  and withholding the pairing card. A first local-routing correction then exposed a second defect:
  hashing an orgless `NotaryValue::single_did(Agent)` omitted the accepted managed-PCR recovery
  members and controller-organization fields, so the receiver rejected the wrong authority digest.
  The next live run exposed a third defect: the receipt used an Agent-owned verification-method
  label even though the active device belongs to the delegated controller, so the receiver correctly
  found no active authorized Agent device key.
- Resolution: the standard publication wrapper recognizes both self-PCR authority and the
  protocol's exact managed Agent delegation shape (`actor_id=Agent`, distinct `executed_by`,
  `authorization_ref=<Agent DID>#managed-controller`). Managed PCR writes re-read the complete
  accepted Event history, validate it through the SDK managed-PCR materializer, and hash the exact
  typed founding `NotaryValue`; their receipt is signed under the `executed_by` controller DID and
  its active device verification method through the shared SDK authoring primitive. Self-PCR
  receipts remain actor-signed, while unrelated Realm control moves still collect receipts from the
  remote current authority. The batch-preparation entry point now calls this same wrapper instead of
  carrying a second local-authority implementation.
- Prevention dimension: receipt routing must derive from the governed Realm's authority model,
  not from whether the PCR id happens to equal the self-principal deterministic id.

## 2026-07-30 — recovery signing identities drifted across four artifact builders

- Severity: P1 lost-device recovery blocker.
- Status: resolved in the key-backup, active-series, rotation, and terminal-receipt paths; the
  four-service B-model happy path now reaches `Completed`.
- Evidence: the same replacement device key was variously labelled `<principal>#device`,
  `<principal>#<device_id>`, and its local `did:key` identity. Service-attested verification
  correctly accepts only the principal- and device-bound method.
- Resolution: every principal control artifact now derives its verification method through
  `verification_method_for_principal`; key-backup upload also resolves the accepted
  `device_authorize_event_id` through viewer or keys-query and re-signs with that trust anchor.
- Follow-up optimization: replace the remaining raw `verification_method()` calls in
  principal-scoped protocol authoring with a single typed `PrincipalDeviceSigner` adapter, so an
  unscoped signer cannot compile at these boundaries.

## 2026-07-30 — recovery restore duplicated trust resolution and ran after generation rotation

- Severity: P1 recovery correctness and maintainability.
- Status: ordering and incorrect cross-service call resolved.
- Evidence: restore queried an Account Authority viewer through a Principal Server transport,
  rebuilt device trust selection independently, and originally downloaded backups after reanchor
  advanced the accepted generation.
- Resolution: restore derives device candidates from accepted active-series Event proofs, uses
  the standard keys query, and durably imports the recovery snapshot before reanchor.
- Follow-up optimization: consolidate backup trust-anchor lookup, active-series verification, and
  recovery-session unlock authoring behind one typed SDK workflow. The legacy
  `fetch_key_backup_for_verified_recovery_session` API still lacks recovery key material and should
  be removed or replaced rather than retained as a misleading partially usable entry point.

## 2026-07-30 — managed Agent authority lookup replayed transitions without frozen pre-state

- Severity: P1 Agent replacement blocker.
- Status: resolved; covered by the managed-PCR authority regression and the live replacement gate.
- Evidence: the first pairing succeeded, but the replacement Agent's runtime-key approval failed
  while deriving the immutable proposal authority. The lookup replayed the complete accepted PCR
  history through a stateless materializer; a later `ak.agent.key.revoke` correctly required frozen
  pre-state that this authoring path cannot supply.
- Resolution: authority lookup now selects the one accepted `ak.realm.create`, validates that
  delegated managed-PCR genesis and its complete leaf set, and derives the immutable notary digest
  from that create alone. Later state transitions no longer participate in genesis-authority
  derivation.
- Prevention dimension: immutable genesis authority and current materialized state are different
  queries. Callers that only need the former must not replay pre-state-dependent transitions.

## 2026-07-31 — inkson main did not compile against arkret-rust-sdk HEAD (Realm authority root)

- Severity: P0 build blocker; also blocked `cotest`, which takes `inkson` as a path dependency.
- Status: resolved upstream by `inkson@0467778e` "Author Realm genesis against the authority
  root"; recorded because the workspace sat un-buildable on a published main in the interval.
  Not caused by the mention-sidecar work landed in the same session; confirmed by `git stash`
  on a clean tree.
- Evidence: `cargo check --all-targets` at `inkson@a054fec3` against `arkret-rust-sdk@19a32f8f`
  ("Own the Realm authority root and split the two aggregate questions") reports 7 errors:
  `arkret_policy::realm_bootstrap::REALM_FOUNDING_GRANT_ACTIONS` is gone
  (`src/operation/ak_ops/capability.rs:155`, `src/transport/tests/envelopes_payloads.rs:100`);
  `SelfPrincipalPcrCreateInput` gained `capability_action_registry_digest`
  (`src/identity/principal_registration.rs:277`); `DirectConversationMaterializationDraft` no
  longer carries `founding_grant_event` / `main_strand_grant_event`
  (`src/transport/account.rs:567,585,664,677`); `Realm::new` now takes the registry basis as a
  seventh parameter (`src/event_builders.rs:390`).
- Why it was not mechanical: `src/transport/account.rs` bootstrapped a direct conversation by
  submitting a founding capability grant and then a main-Strand grant chained through
  `authorization_ref`. The authority-root model removes that chain, so the client-side
  materialization sequence has to be re-derived from what `soland@2bf010fa` now materializes rather
  than have the two grant submissions deleted in place.
- Prevention dimension: `arkret-rust-sdk` breaking changes land as compile errors in every
  consumer by design, but `inkson` and `cotest` were not carried in the same sweep as `soland` and
  `garth`, so the workspace sat un-buildable on main.

## 2026-07-31 — MLS runtime backup/secret tests fail under parallel execution

- Severity: P2 test-suite reliability; a green run is not reproducible.
- Status: open.
- Evidence: `cargo test --lib mls::runtime` fails 4-6 of `genesis_backup::*` and
  `secret::account_secret_rotation_rewraps_backups_old_secret_cannot_decrypt`, and the failing set
  differs between runs. The same selection passes 59/59 with `--test-threads=1`.
- Prevention dimension: these cases share durable state (snapshot store / secure key store) across
  the default parallel test threads, so an unrelated change appears to break MLS backup at random.
  Each case needs its own isolated store rather than a shared default path.
