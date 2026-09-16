# Authority-commit client capability migration

Inkson remains the cross-platform Arkret product client. Passing compilation with
a protocol-only shell is not an acceptable migration result.

## Status

The full product baseline is present in the working tree. It is an exact
restoration of the tree that preceded the protocol clean-break commit: the index
is byte-identical to `57a4ea10` (`git diff --cached HEAD~1` is empty), covering
524 Rust source files (261,882 lines), 1,912 inline test functions across 256
files, 15 integration test binaries, the Playwright e2e / contract /
cross-platform suites, platform assets, packaging scripts, release workflows and
user guides.

The baseline does **not** yet build against the current SDK. `cargo check
--lib --all-features` reports 1,586 errors and `cargo test --workspace
--all-features --no-fail-fast` reports 2,154 errors in `lib test`; no test
binary links, so no test result counts exist. The cause is upstream, not local:
the client runtime crate (`garth`) and the SDK facade were reduced at the same
time the client tree was, and 249 distinct types the product depends on are
absent from the SDK. 45 of those are protocol surfaces this migration is meant to
delete; the remaining 204 are product surfaces with no replacement yet.

Migration of the call sites cannot begin until the replacement seams exist. No
compatibility alias, local protocol type, empty implementation or deleted
product module has been introduced to shorten this list.

## Product and platform capabilities preserved

Every capability below is present in the tree with the implementation and test
evidence named. None was deleted by the clean-break commit's restoration.

| Capability | Implementation | Behavior tests |
| --- | --- | --- |
| Desktop, web and mobile shells, routing, navigation, i18n | `src/app/` (`session_shell.rs`, `route_surface.rs`, `navigation_state.rs`, `sidebar.rs`, `command_palette.rs`), `src/routes.rs`, `src/views/mod.rs`, `src/i18n/{en,zh}.rs`, `src/styles/` | `src/app/shell_model_tests.rs`, `src/i18n/tests.rs`, `tests/i18n_dictionaries.rs`, `tests/locale_sync.rs`, `tests/ui_text_gate.rs`, `tests/ui_compile.rs`, `tests/e2e/viewport.spec.ts` |
| Login, session refresh, DPoP, onboarding, device pairing, account handoff | `src/views/login/`, `src/identity/account_auth/`, `src/identity/session_refresh.rs`, `src/views/onboarding/` (`account_commit.rs`, `device_pairing.rs`, `resume.rs`), `src/identity/device_pairing.rs`, `src/views/register.rs`, `garth::session`, `garth::account_handoff` | `src/views/login/tests.rs`, `src/views/onboarding/tests.rs`, `tests/dev_token_guard.rs`, `tests/e2e/inkson.strands.auth-session.spec.ts`, `tests/cross_platform/oidc_pkce.spec.ts` |
| SecureKeyStore backends, IndexedDB / native persistence, cancellation-safe durable state | `src/secure_key_store/` (`indexed_db.rs`, `local_storage.rs`, `keyring.rs`, `platform.rs`, `host_bridge.rs`, `fallback.rs`, `current_index_backend.rs`), `src/state/`, `src/browser_storage.rs`, `src/outbound_store.rs` | `src/secure_key_store/tests.rs`, `tests/wasm_indexed_db_capacity.rs`, `tests/wasm_current_index.rs`, `src/local_state_tests/store_persist.rs`, `tests/cross_platform/local_storage.spec.ts`, `tests/cross_platform/subtle_crypto.spec.ts` |
| Chat, Direct Conversation, reactions, polls, read receipts, mentions | `src/views/chat/` (`timeline.rs`, `composer/`, `controller.rs`, `poll_submission.rs`, `direct_authority.rs`), `src/messaging/` (`polls.rs`, `mentions.rs`, `discussion_promote.rs`), `src/views/read_receipts.rs`, `src/state/direct_conversation.rs`, `src/content/renderer.rs` | `src/views/chat/tests/` (15 modules incl. `mentions.rs`, `read_receipts.rs`, `message_fold.rs`, `participation.rs`), `src/local_state_tests/read_receipt.rs`, `tests/e2e/inkson.strands.chat-discussion.spec.ts` |
| Circle, Realm, Space, Strand, Kanban, calendar and relation views | `src/circle.rs`, `src/circle_mls.rs`, `src/realm_tree.rs`, `src/realm_helpers.rs`, `src/views/setup/`, `src/views/kanban/`, `src/calendar.rs`, `src/views/kanban/due_calendar.rs`, `src/views/kanban/assignment.rs` | `src/views/kanban/tests/` (11 modules incl. `lifecycle.rs`, `roster.rs`, `encrypted_scope.rs`, `due_calendar.rs`), `tests/e2e/inkson.strands.kanban.spec.ts`, `tests/e2e/inkson.strands.realm-nav.spec.ts`, `tests/e2e/realm-create-regression.spec.ts`, `tests/e2e/inkson.strands.setup-realm-admin.spec.ts` |
| Directory, contacts, profiles, moderation, notifications, account settings | `src/views/directory.rs`, `src/views/contacts.rs`, `src/views/member_display.rs`, `src/views/moderation.rs`, `src/views/notifications/`, `src/views/settings/`, `src/identity/contact_profile.rs`, `src/directory_helpers.rs`, `src/notification_rules.rs` | `src/views/notifications/tests.rs`, `src/views/settings/tests.rs`, `src/views/settings/model_tests.rs`, `src/account_data/tests.rs`, `tests/e2e/inkson.strands.notifications-directory.spec.ts`, `tests/e2e/inkson.strands.account-settings.spec.ts` |
| File transfer, media / WebRTC, push, scheduled send, platform packaging | `src/file_transfer.rs`, `src/blob.rs`, `src/media/` (`rtc.rs`, `service_route.rs`, `http_fetch.rs`), `src/rtc_transport/{native,web}.rs`, `src/webrtc.rs`, `src/push/`, `src/scheduled_send.rs`, `src/views/call/`, `assets/livekit_*`, `scripts/{windows-msi,macos-bundle,linux-package}-local.ps1`, `Dockerfile` | `src/push/tests.rs`, `src/views/file_transfer.rs` inline tests, `tests/cross_platform/push_subscribe.spec.ts`, `tests/cross_platform/push_receive.spec.ts`, `.github/workflows/packages.yml`, `.github/workflows/cross-platform.yaml` |
| Account / device recovery, key backup, SecurityTransaction flows | `src/recovery_flow.rs`, `src/fresh_device_recovery.rs`, `src/late_recovery.rs`, `src/recovery_crypto.rs`, `src/hpke_backup.rs`, `src/key_backup/`, `src/security_transaction.rs`, `src/mls/account_recovery/`, `src/views/recovery/`, `src/components/recovery_key_setup_prompt.rs` | `src/views/recovery/tests.rs`, `src/key_backup/tests.rs`, `src/account_data/tests.rs`, `tests/e2e/inkson.strands.recovery-encryption.spec.ts`, `docs/user-flows-key-lifecycle.md` |
| MLS group lifecycle, local private state, KeyPackage maintenance, staged commit install, encryption | `src/mls/` (`runtime/`, `admission.rs`, `accepted_artifact.rs`, `group_events.rs`, `persistence.rs`, `creator_bootstrap.rs`, `direct_binding.rs`, `coverage_liveness.rs`, `pairwise_identity.rs`), `src/circle_mls.rs`, `src/keypackage_maintenance.rs`, `src/state/mls_*.rs` | `tests/mls_data_plane_wasm.rs`, `src/local_state_tests/mls_local_checkpoint.rs`, `src/local_state_tests/private_plaintext.rs`, `src/views/kanban/tests/strand_mls.rs`, `src/views/chat/tests/crypto_state.rs` |
| Signal / WebSocket receive, retry / offline queue, observable sync state | `src/signal.rs`, `src/signal_receive_engine.rs`, `src/websocket_rail_engine.rs`, `src/transport/{websocket,websocket_rail}.rs`, `src/sync_engine.rs`, `src/sync_parse.rs`, `src/realm_events_engine.rs`, `src/outbound_store.rs`, `src/components/sync_badge.rs` | `tests/client_core_dedup_guard.rs`, `tests/server_contract.rs`, `src/local_state_tests/sync_states.rs`, `src/transport/tests/`, `tests/e2e/mock-arkret-api-contract.spec.ts` |
| Accessibility, keyboard shortcuts, error classification, tests, release CI | `src/components/shortcut_help.rs`, `src/app/command_palette.rs`, `src/api_error/`, `src/telemetry.rs`, `docs/unified-keyboard-shortcuts.md`, `.github/workflows/{ci,compatibility,cross-platform,deny,docker,packages,typos,line-endings}.yml`, `scripts/{gate,clippy_gate,deletion_gate}.sh`, `scripts/release-gate.ps1` | `tests/ui_text_gate.rs`, `tests/authz_action_registry_guard.rs`, `tests/conformance_gates.rs`, `tests/conformance_vectors.rs`, `tests/e2e/viewport.spec.ts`, `docs/RELEASING.md` |

## Protocol seams to replace

- [ ] Author producer-signed Events without actor sequence, predecessor, causal,
  Seal or Cell fields. Blocked: `src/event_builders.rs`, `src/operation/`,
  `src/move_builder.rs` still build `SealBasis` / `Precondition` /
  `ProjectedCellWrite` / `LatticeOp` shapes; no replacement authoring type is
  exposed yet.
- [ ] Submit through the authenticated current governance Station and expose
  queued/forwarding/committed/rejected outcomes. Partially available:
  `arkret_wire::EventCommitSubmission { event }` and
  `garth::{AuthorityClient, AuthorityTransport, QueuedSubmission,
  SubmissionState, SubmissionWorker, SubmissionQueueStore}` exist. Blocked:
  `src/event_submit.rs` and `src/outbound_store.rs` are written against the
  removed `garth::outbound` engine (`OutboundEngine`, `OutboundSubmitter`,
  `OutboundPostAcceptHook`, `QueuedEventIntent`, `QueuedRealmBootstrap`,
  `OutboundGenerationFence`), which has no successor.
- [ ] Verify independent Realm, Circle and Sidecar RealmCommit chains; never
  create a Realm-global total order. Blocked: `garth::RealmReplica` /
  `garth::StreamReplica` exist but the client-side projection layer
  (`garth::projection`, `ClientProjector`, `ClientEvent`,
  `expand_realm_delivery_events`) that `src/realm_events_engine.rs`,
  `src/runtime/projection.rs` and `src/app/projection_adapter.rs` consume was
  removed with no replacement.
- [ ] Join by authenticating the current authority chain and installing a typed
  snapshot plus authorized per-stream tails. Blocked: `src/bootstrap.rs` and
  `src/transport/invite_join.rs` need the typed snapshot and per-stream tail
  read surfaces; only `RealmAuthorityBundle` /
  `RealmAuthorityCurrentAssertion` are present.
- [ ] Reject writes from an old authority after planned handoff and fail closed
  when no authenticated current authority can be established. Not started;
  depends on the submit seam above.
- [ ] Remove only the old Seal/Cell/CBS/frontier/fork-resolution
  implementations; migrate every product feature above to the new seams. Not
  started; removal without a replacement seam would empty the product modules.

## Upstream blockers

### `garth` (client runtime)

`garth` was reduced from ~38,000 to 7,530 lines in `6465775`. The removed
modules are exactly the runtime layer `inkson` sits on. 349 of the 1,586 errors
resolve to `garth`.

Absent, consumed by `inkson`: `outbound` (engine, submitter, post-accept hooks,
generation fence, queued intents/records, `OutboundQueueStore`), `projection`
(`ClientProjector`, `ClientEvent`, `ProjectionObjectState`,
`realm_projection_is_encrypted`, `realm_projection_security_state`,
`security_projection_for_scope_id`), sync loop control (`SyncLoopControl`,
`RunOptions`, `RunStopReason`, `ScanCatchupOptions`, `TransportProvider`,
`RealmEventsTransport`, `RealmEventsFrameSource`, `expand_realm_delivery_events`),
`history_runtime` / `HistoryCandidateEngine` / `HistorySourceAttemptStatus`,
`SignalPlaintext` / `SignalReceiveHandlers` / `SignalRejection`,
`SendQueueStatus`, `InstalledMlsEpoch`, `LocalSealView`, `AuthoringGeneration` /
`AuthoringAuthorityModel`, and the `garth::mls` submodules `welcome_admission`,
`backup_selection`, `backup_series`, `local_checkpoint`, `device_secret`,
`self_preservation`, `status`. `garth::message_authoring` exists but no longer
exports `MessageAuthoringSession`, `MessageAuthoringTarget`,
`MessageAuthoringFailure` or `MessageAuthoringRecovery`.

One unrelated compile break was repaired to make the census possible:
`garth/src/direct_conversation.rs` had not followed
`DirectConversationResolveOutcome` to its current shape (`CreationRequired` is
now a struct variant, and `CreationBlocked`, `AwaitingFounder`,
`ProvisionallyCommitted` were unhandled). That change is in the `garth` tree,
not this repository.

### `arkret-rust-sdk`

249 distinct symbols `inkson` imports are absent. 45 are the protocol surfaces
this migration removes on purpose (`Seal*`, `Cell*`, `Cbs*`, `*Frontier*`,
`Lattice*`, `ControlProposal*`, `Predicate`/`PredicateOp`/`Precondition`,
`EventRequirements`, `ProjectedCellWrite`, `ProjectionEffect`, `ProjectedOp`,
`StateWrite`, `DurabilityPolicy`, `causal_register_state`,
`ConsentObservedDot`, `EventInitialSubmission`,
`EventsSubmitBatchRequestBody`, `CORE_REDUCER_PROFILE`). Their call sites are
migration work, not blockers.

The other 204 are product surfaces with no successor. By family:

| Family | Absent symbols (count) | Examples |
| --- | --- | --- |
| History key request/response, exporter history | 28 | `HistoryKeyRequest`, `HistoryKeyRequestRecord`, `HistoryKeyResponseContent`, `HistoryResponsePageEntry`, `VerifiedHistoryResponseRecord`, `HistoryEffectiveScope`, `history_store` |
| Agent runtime and Agent Sidecar | 19 | `AgentSidecarView`, `AgentSidecarExchangeProjection`, `AgentSidecarMlsContext`, `AgentRuntimeApprovalControllerProjection`, `AgentSenderKind`, `agent_sidecar_view_state_account_data_key` |
| Account/device recovery policy | 17 | `RecoveryPolicy`, `RecoveryKeyEntry`, `RecoveryMethod`, `RecoverySessionState`, `RecoverySessionProof`, `UnsignedRecoveryReceipt`, `RecoveryIdentityModel` |
| MLS Welcome delivery and accepted artifacts | 12 | `MlsWelcomeCarrier`, `MlsWelcomePayload`, `MlsWelcomeRecipient`, `MlsAcceptedArtifactOutcome`, `MlsMembershipRemovalOutcome`, `MlsEpochHead`, `MlsClaimTrustBinding` |
| Direct Conversation founding | 6 | `direct_conversation_ops`, `DirectConversationFoundingPlan`, `DirectConversationSummary`, `DirectConversationSummaryState` |
| Account subscribe / commit stream | 6 | `AccountStreamStep`, `AccountStepHandlers`, `AccountCommitOutcome`, `AccountPostCommitHook` |
| Current-index projection reads | 5 | `CurrentTarget`, `CurrentOutcome`, `CurrentEntries`, `CurrentResultEntry`, `CurrentMemberCoverage` |
| Realm/Space/Strand projection rows | 5 | `ProjectionSpaceRow`, `ProjectionStrandRow`, `ProjectionObjectState`, `RealmRow`, `RealmListMembership` |
| Events read/submit outcomes | 6 | `EventReadRow`, `EventsQueryOutcome`, `EventsSubmitOutcome`, `EventsSubmitStatus`, `EventsSubmitRejectedRow`, `EventsSubscribeFrame` |
| Contacts, notifications, consent, MIMI, sidecar ops | 10 | `ContactState`, `ContactListRow`, `NotificationData`, `ConsentState`, `MimiSubmitMessageOutcome`, `sidecar_operations` |
| Session, key backup, device pairing, other | ~90 | `SessionState`, `SessionGrantIntrospectionProof`, `KeyBackupKeybag`, `KeyBackupContentIndex`, `UnsignedKeyBackup`, `DevicePairingReadyForClaimState`, `UnsignedDeviceAuthorizePayload`, `device_authorize_payload_digest`, `AuthContext`, `AuthorProfile`, `PolicyDocument`, `MemberRosterEntry`, `ReadCursorPosition` |

A further 75 symbols do exist in the SDK workspace but are no longer reachable
from the `arkret_sdk` facade root. These are a re-export gap, not a design gap;
restoring the facade exports (or repointing the imports) clears them:

- `arkret_models_collaboration` (42): `AccountView`, `AccountRegisterRequestBody`,
  `AccountDevicePairOutcome`, `AccountSubscribeFrame` and its kinds,
  `AgentView`, `AgentProjection`, `AgentRuntimeState`, `AgentSidecarView`,
  `AgentPairingBootstrap`, `AgentRequestedScopeDisclosure`, `ContactList`,
  `DeviceMessageEnvelope`, `DeviceMessageSender`, the `DevicePairing*` family,
  `KeyState`, `NotificationDelta`, `NotificationDeltaAction`, `RealmSyncEntry`,
  `SessionGrantOutcome`, `SessionGrantRequestBody`,
  `SessionGrantRefreshRequestBody`, `SignalSubmitOutcome`, `SyncFilter`,
  `SyncRequestBody`, `StationCasAccountDataContainer`,
  `human_session_grant_intent_digest`.
- `arkret_models_crypto` (24): `SecurityTransaction`,
  `SecurityTransactionCreateRequest`, `SecurityTransactionStep`,
  `SecurityRotationTransactionCreateRequest`, `RecoveryTransactionCreateRequest`,
  `RecoveryAuthorityKind`, `RecoveryIdentityModel`, `PcrPolicyRecoveryIntent`,
  `PreparedEventUnit`, `BackupObjectRef`, `BackupRotationKind`,
  `BackupRotationPlan`, `BackupRotationBinding`, `BackupActiveSeriesState`,
  `KeyBackupSummary`, `KeyBackupUnlockProof`, `KeyBackupUnlockAuthority`,
  `KeyBackupsListQuery`, `KeysBackupsList`, `KeysBackupsReplaceOutcome`,
  `KeysBackupsUnlockChallenge`, `MlsProposalEnvelope`, `MlsWelcomeEnvelope`.
- `arkret_wire` (6), `arkret_retry` (1: `RetrySchedule`), `arkret_http_client`
  (1: `KeyBackupClient`), `arkret_event_draft` (1: `AgentLifecycleState`).

Expected but not yet present anywhere: a typed MLS Welcome **delivery** object
(the producer-signed recipient delivery object that is not an Event), and the
`policy_revision` replacement for `policy_root`.

## Residue census

Full-tree grep, ordinary-English senses separated by hand. These are old-protocol
call sites awaiting the replacement seams, not stray text.

| Term | Occurrences (`src/`, `tests/`) | Notes |
| --- | --- | --- |
| `Seal` | 1,317 tree-wide | Protocol sense throughout `views`, `mls`, `transport`, `state`. `hpke_seal` / `seal`-`open` in `src/hpke_backup.rs` and `src/recovery_crypto.rs` is RFC 9180 HPKE and stays. |
| `Cell` | 893 tree-wide; 143 protocol-sense identifiers | The remainder is `std::cell::RefCell` / `OnceCell` and the word "cancel". Protocol-sense: `cell_id` (79), `CellRef` (15), `CellFamilyId` (10), `cell_ref` (10), `cell_value`, `cbs_cell_family_plane`. |
| `frontier` | 850 | Concentrated in `src/mls/` (227) and `src/views/` (185). No ordinary-English sense present. |
| `CBS` | 83 | Mostly `src/event_submit.rs` (19) and `src/identity/` (11). |
| `ControlProposal` | 26 | All protocol sense. |
| `lattice` | 22 | All protocol sense. |
| `or_set` | 7 | All protocol sense. |
| `causal_register` | 5 | All protocol sense. |
| `RHRK` | 6 | All protocol sense. |
| `history_secret` | 166 | `src/state/` (52), `src/mls/` (49), `src/secure_key_store/` (27). |
| `exporter` | 286 | Split. RFC 9420 MLS exporter for SFrame in `src/media/` (86) and `src/rtc_transport/` (18) is required by spec and stays. The "history exporter" sense is `scope_uses_exporter_history` in `src/history_recovery.rs` and the exporter-history ranges in `src/mls/runtime/history_candidate_consumer.rs`. |
| `encryption_profile` | 155 | Create-locked profile, to be removed; SDK field rename pending. |
| `encryption_floor` | 95 | Content/metadata floor, to be removed; `src/components/encryption_floor_prompt.rs` is the UI surface. |
| `mls_welcome` | 93 | Welcome-as-Event call sites; awaiting the typed delivery object. |
| `Retired` | 83 | Two senses. `src/state/current_index.rs` uses `RetiredEntry` / `retired/` as a live current-index concept, not a tombstone narrative. `src/views/`, `src/mls/`, `src/transport/` carry tombstone prose that must go. |
| `Legacy` | 21 | Tombstone narrative, e.g. `accepted_legacy_creator_genesis_proposal` in `src/event_submit.rs`. |
| `Deprecated` | 4 | Tombstone narrative. |
| `sequenced_state`, `authority_revision`, `policy_root` | 0 | Already absent. |

## Verification gates

- [ ] Every capability above maps to a retained implementation and behavior test;
  passing a protocol-core unit test set is not sufficient. **Implementation and
  test evidence are recorded above. The tests cannot execute: the crate does not
  compile.**
- [ ] Native and WASM builds, UI/contract tests, IndexedDB/native persistence,
  MLS, media, push and packaging checks pass against the final SDK. **Blocked on
  the native build.**
- [x] The final diff does not delete an application surface, platform asset,
  release workflow or user guide merely because its old transport used removed
  protocol types. **Verified: the working tree is an exact restoration of
  `57a4ea10`; nothing is missing and nothing extra was added.**

## Command results

| Command | Result |
| --- | --- |
| `cargo +nightly fmt --check` (inkson only) | Clean, exit 0. No rewrite needed. |
| `cargo check --workspace --all-features` | 1,586 errors in `inkson` (lib). |
| `cargo test --workspace --all-features --no-fail-fast` | 2,154 errors in `inkson` (lib test); no test binary links, no pass/fail counts. |
| wasm build / wasm browser tests | Not attempted: `dx build --platform web` and `tests/mls_data_plane_wasm.rs` both require the crate to compile first. |
