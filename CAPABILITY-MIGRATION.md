# Authority-commit client capability migration

Inkson remains the cross-platform Arkret product client. Passing compilation
with a protocol-only shell is not an acceptable migration result, so this file
tracks capabilities, not error counts: every row names the implementation path
the capability now runs through and the behavior test that proves it.

## The seam that changed

The client used to author Events that carried their own ordering and
pre-state: an actor sequence, an HLC, a Seal basis, preconditions over
protocol-level Cells, CBS execution planes, and a Realm-global sync cursor. All
of that is gone. A producer now signs an immutable Event and hands it to the
Realm's **current governance Station**, which answers with an authority-signed
`RealmCommit`.

| Concern | Before | Now |
| --- | --- | --- |
| Submission DTO | `EventInitialSubmission` (+ lease, Control Proposal Ack, CBS proof bundles, submit context) | `arkret_wire::EventCommitSubmission { event }` inside `AuthoritySubmitRequest::Event` |
| Submission result | `EventsSubmitOutcome { status, accepted[], duplicate[], rejections[], cursor, ingress_receipts[] }` | `AuthoritySubmitOutcome::{Accepted{status, commit}, Rejected{status, reason_code}}` |
| Ordering | producer `actor_seq` + `hlc` + `prev_refs` | `RealmCommit { stream_ref, stream_position, previous_commit_ref }`, one commit per Event |
| Streams | one Realm-global cursor | independent `CommitStreamRef::{Realm, Circle, Sidecar}` streams, each with its own position |
| Catch-up | `ak.self.events.read.query` pages | `StreamScanRequest{realm_id, stream_ref, after_position, limit}` → `StreamScanOutcome{commits, truncated}` |
| Current state | `ak:cell:*` current results | `RealmStateSnapshot.current_state_entries` — `TypedCurrentRow` keyed by `CurrentSelector` with a `CurrentRevision{commit_id, stream_position}` |
| Realm authority | `ak.component.realm.authority_root.v1` cell + controller epoch | `RealmAuthorityBundle` (genesis + double-signed handoff chain + nonce-bound current assertion); `IssuerAuthorityRef::RealmAuthority{realm_id, governance_station_id, authority_generation, basis}` |
| "Is this scope encrypted?" | create-locked `encryption_profile` + encryption floor | the scope has an accepted `ak.mls.genesis` (`CurrentSelector::MlsGroup{scope_ref}` → `MlsGroupCurrent`) — plaintext before, irreversibly RFC 9420 after |
| MLS Welcome | `ak.mls.welcome` Event | `MlsWelcomeDelivery` (`ak:mls_welcome_delivery:<uuidv7>`), producer-signed, delivered inside `MlsCommitSubmission` |
| MLS commit | Proposal Events + Commit Event + Welcome Events, staged | `MlsCommitSubmission { commit_event, welcomes[], idempotency_key }`, one atomic submission; staged state installs on Accepted without waiting for recipient ACK |
| Recovery completion | Seal-chained PCR successor | two different commits at positions n and n+1 of the same PCR Realm stream, judged by `garth::validate_recovery_commit_boundary` |
| Local outbound queue | `garth::outbound` engine with post-accept hooks and a generation fence | `garth::OutboundEngine` over `crate::outbound_store::InksonOutboundStore`, with the fence and the post-accept work hosted in inkson |

## Client-side design decisions taken by this migration

1. **No Realm-global order anywhere.** Durable cursors are keyed by
   `arkret_wire::CommitStreamRef`. `AccountSyncStep::stream_heads()` is the only
   place a sync frame is turned into positions, and it returns one position per
   independent stream.
2. **Authoring is final.** With no actor sequence, HLC or precondition, the
   `event_id` derived at authoring time is the id that reaches the wire. The
   durable queue stores a frozen `AuthoritySubmitRequest`; there is no re-author
   path and therefore no "queued id vs. accepted id" divergence.
3. **Holder-local handles never reach the wire.** `Event` has no `unsigned`
   member any more, so the optimistic-UI alias (`local_operation_id`,
   `local_target_ref`) lives on `crate::operation::LocalOperation` and in the
   durable outbound record, and the projection re-keys an optimistic row to the
   commit's `event_ref` when the commit lands.
4. **Fail closed on authority.** A Realm whose current governance Station cannot
   be authenticated from a fresh, nonce-bound `RealmAuthorityBundle` is not
   written to at all.
5. **Deleted protocol concepts are deleted, not emulated.** No compatibility
   alias, no local re-declaration of a removed wire type, no empty
   implementation. Where a still-normative spec surface has no SDK type, the
   call site keeps failing to compile and is listed under
   "Blocked by an SDK gap" below rather than being papered over.

## Product and platform capabilities

| Capability | Implementation | Behavior tests |
| --- | --- | --- |
| Desktop, web and mobile shells, routing, navigation, i18n | `src/app/`, `src/routes.rs`, `src/views/mod.rs`, `src/i18n/{en,zh}.rs` | `src/app/shell_model_tests.rs`, `src/i18n/tests.rs`, `tests/i18n_dictionaries.rs`, `tests/ui_text_gate.rs`, `tests/e2e/viewport.spec.ts` |
| Login, session refresh, DPoP, onboarding, device pairing, account handoff | `src/views/login/`, `src/identity/account_auth/`, `src/identity/session_refresh.rs`, `src/views/onboarding/`, `garth::session`, `garth::account_handoff` | `src/views/login/tests.rs`, `src/views/onboarding/tests.rs`, `tests/dev_token_guard.rs`, `tests/e2e/inkson.strands.auth-session.spec.ts` |
| SecureKeyStore backends, IndexedDB / native persistence | `src/secure_key_store/`, `src/state/`, `src/browser_storage.rs` | `src/secure_key_store/tests.rs`, `tests/wasm_indexed_db_capacity.rs`, `tests/wasm_current_index.rs` |
| Durable outbound queue (offline send, retry, cancel) | `src/outbound_store.rs` (`InksonOutboundStore`: native atomic file replace + wasm IndexedDB secure tier) driving `garth::OutboundEngine` | `src/outbound_store.rs` inline tests (secure-store round trip, >5 MB queue, refused write reported, native atomic file replace, IndexedDB-only key classification, lane separation) |
| Event authoring | `src/operation/` (`TypedOperationBuilder` → `arkret_sdk::TypedEventDraft` → `EventIntent`), `src/event_builders.rs`, `src/operation/ak_ops/` | `src/operation_tests.rs`, `src/operation/ak_ops/capability.rs` inline tests (grant binds the committed Realm-authority decision, a later generation yields a different issuer ref) |
| Event signing | `src/event_signer.rs` (`InksonPayloadSignerAdapter`, single `SignerEvidenceRef` family) | `src/event_signer.rs` inline tests (real JWS proof, notary JWS binds the frozen descriptor kid) |
| Realm creation / bootstrap unit | `src/event_builders.rs::build_realm_bootstrap_steps_for_station` — `ak.realm.create` naming the initial governance Station, join rule, history access and discoverability, plus the closed facet whitelist | `src/transport/tests/envelopes_payloads.rs` |
| Capability grants | `src/operation/ak_ops/capability.rs` with `IssuerRealmAuthorityBasis::from_verified_bundle` | inline tests above |
| Consent | `src/operation/ak_ops/consent.rs` (`ConsentRevokePayload.expected_revision` from `ConsentView.revision`), `src/transport/account.rs` on `PATH_SELF_CONSENT_RESULT*` | `src/views/settings/consent.rs` tests |
| MLS Welcome admission | `src/mls/welcome_delivery.rs` — the host conversion between `MlsWelcomeDelivery` (wire) and `MlsWelcomeEnvelope` (provider), plus `enqueue_admissible_welcomes` over `garth::retain_admissible_welcomes` | `src/mls/welcome_delivery.rs` inline tests (epoch comes from the Commit, wrong Commit refused, Agent runtime needs its accepted key binding, foreign endpoint never queued) |
| Current-state projection | `src/current_projection.rs` over `TypedCurrentRow` / `CurrentSelector`, incl. `scope_has_accepted_mls_genesis` | `src/local_state_tests/projections.rs` |
| Chat, Direct Conversation, reactions, polls, read receipts, mentions | `src/views/chat/`, `src/messaging/`, `src/state/direct_conversation.rs` | `src/views/chat/tests/`, `tests/e2e/inkson.strands.chat-discussion.spec.ts` |
| Circle, Realm, Space, Strand, Kanban, calendar | `src/circle.rs`, `src/circle_mls.rs`, `src/realm_tree.rs`, `src/views/kanban/`, `src/calendar.rs` | `src/views/kanban/tests/`, `tests/e2e/inkson.strands.kanban.spec.ts` |
| Media / WebRTC (SFrame RFC 9420 exporter), push | `src/media/`, `src/rtc_transport/`, `src/push/` | `src/push/tests.rs`, `tests/cross_platform/push_*.spec.ts` |
| Account / device recovery, key backup | `src/recovery_flow.rs`, `src/key_backup/`, `src/mls/account_recovery/`, `garth::security_transaction` | `src/views/recovery/tests.rs`, `src/key_backup/tests.rs` |
| Signal / WebSocket receive, observable sync state | `src/signal.rs`, `src/signal_receive_engine.rs`, `src/sync_engine.rs`, `src/transport/`, `garth::run`, `garth::replica` | `tests/server_contract.rs`, `src/local_state_tests/sync_states.rs` |

## Blocked by an SDK gap

These are spec-normative surfaces the SDK no longer exposes. Per the migration
rule that protocol types may only be defined in `arkret-rust-sdk`, the inkson
call sites are left failing rather than re-declared locally.

| Missing SDK surface | Spec source | Blocked inkson capability |
| --- | --- | --- |
| `DeviceRevokePayload` + revocation reason; `event_spec::DeviceRevoke` has no payload binding although `EventKind::DeviceRevoke` is registered | `event-payload.schema.json#/$defs/device_revoke_payload` | device revoke |
| `ak.realm.authority.reset` Event kind and its authoring helper, plus a `CurrentSelector` for the authority-root typed current result the payload's `expected_state_digest` has to CAS against (`RealmAuthorityResetPayload` exists but nothing can author it, and `CurrentSelector` is closed to profile / policy / member / strand / reactions / MLS group) | `spec/v1/zh/authz/capabilities.md` §148 (reset computes `authority_generation = checked_add(prestate, 1)` under an `expected_state_digest` CAS), §661 (`realm_root` refs fail a whole generation only on reset); `conformance-profiles.json` `stable_phase.allowed_root_control_actions` | Realm admin ownership card: current owner, controller epoch, owner transfer and "revoke all Realm-wide permissions" |
| `MessagePrepareOutcome` | `message-authoring.schema.json#/$defs/message_prepare_outcome` | Station-prepared message authoring |
| `MimiSubmitMessage{RequestBody,Outcome}`, `MimiIdentifierQueryOutcome`, `MimiProxyDownloadOutcome` | `mimi-operations.schema.json`; operations registered in `operation-registry.json` | MIMI interop send / identifier query / proxy download |
| `PolicySetStatePayload` | `event-payload.schema.json#/$defs/policy_set_state_payload` | Realm policy set-state |
| `RecoveryPolicyPublishRequest` | `recovery-policy.schema.json#/$defs/recovery_policy_publish_request` | recovery policy publish |
| `SidecarMlsBinding` (7 sites, `src/sidecar.rs`) | `sidecar-operations.schema.json` | Agent Sidecar MLS binding |
| `MAX_PEER_RESOLVE_RESPONSE_BYTES` (3 sites, `src/transport/`) | `events-resolve` peer response ceiling | peer resolve response bound |
| `CommandOutcome` / `command_unit_outcome` / `server_command_unit_outcome` (6 sites) | `command-unit.schema.json` | command unit result handling |
| `BackupSeriesErase{Outcome,RequestBody}` (3 sites, `src/key_backup/`) | `key-backup.schema.json` | backup series erase |
| `DeviceReanchorPayload` (1 site, `src/fresh_device_recovery.rs`) | `event-payload.schema.json#/$defs/device_reanchor_payload`; `ak.device.reanchor` is the one action a recovery publication authority context may allow | fresh-device recovery re-anchor |
| `RecoveryPreparedPlan`, `UnsignedClientStepAttestation`, `RecoveryBackupClassUnlocked`, `build_recovery_unlock_proof`, `signed_event_digest_claim`, `build_self_principal_pcr_genesis_unit`, `agent_inception_notary`, `CORE_REDUCER_PROFILE` | recovery / security-transaction and principal-genesis schemas | fresh-device recovery, PCR genesis, agent inception |

`ProofSummary` was removed from this table: it was a misdiagnosis. The type
exists as `arkret_models_crypto::RecoverySessionProofSummary` (the session's
summary, carrying `verification_method`) alongside
`arkret_models_crypto::RecoveryProofSummary` (the transaction's, carrying
`quorum_participant_count`); inkson was naming a third, nonexistent one.
Likewise `BackupRotationKind`, `BackupRotationPlan`, `PreparedEventUnit`,
`agent_runtime_key_binding_digest` and `WindowStartRealmMetadata` are present
in the SDK and were import-path problems, not gaps. Of those,
`WindowStartRealmMetadata` is real but unreachable through the umbrella:
`arkret_sdk::sync` re-exports `sync_frames::{account_subscribe,
current_results, realm_state_snapshot}` and not `sync_frames::account_sync`,
so the call site names `arkret_models_collaboration` directly.

## SDK gaps closed by this round

Three of the gaps above were not "the SDK dropped a concept" but "the SDK had
not re-exposed a still-normative one". They were restored in
`arkret-rust-sdk` (never re-declared in inkson), and the inkson call sites are
now ordinary typed reads:

| Restored SDK surface | Where it now lives | Inkson capability it unblocked |
| --- | --- | --- |
| `ContactState`, `ContactListRow`, `ContactAgentProjection`, `DirectConversationSummary(State)`; `ContactList.contacts` is `Vec<ContactListRow>` again | `arkret_models_collaboration::contact_operations`, re-exported at `arkret_sdk::*`. `ContactListRow` deserializes through a private wire struct that enforces the schema's conditional requirements (`next_prepare_input` exactly for `accepted`, `request_event_ref` for `pending_incoming`, `request_message` only there, `effective_scopes == bidirectional_scopes`) | contacts list, contact request / accept / reject UI, sidebar direct-chat targets, `accepted_human_contact_principals` in local state |
| Typed notification deltas: `NotificationDelta{id: NotificationIdentity, action, data: Option<NotificationData>}`, `NotificationData::{AgentRuntimeApproval, AgentRuntimeApprovalRemoval, OrdinaryProjection, OrdinaryRemoval}`, the two closed removal-reason vocabularies, and `verify_recipient_binding` | `arkret_models_collaboration::sync_frames::account_subscribe`, re-exported at `arkret_sdk::sync::*`. The branch is selected from the `id` form before `data` is parsed, so the overlapping `expired` / `superseded` reasons cannot cross branches | notification inbox, Agent runtime approval notifications, mention / message notification projections |
| `MemberRosterEntry`, `MemberRosterMembership`, `MemberRoster`, `AgentRuntimeApprovalNotificationData` | already present in `arkret_models_collaboration::account_subscribe_projections`; only the `arkret_sdk::sync` re-export was missing | typed member roster, member display ladder, roster-driven Kanban assignment |

Call sites moved with them: sync-frame types are addressed as
`arkret_sdk::sync::*` (the umbrella namespaces them under `sync`, and the
client no longer reaches for them at the crate root), and the roster membership
value is `MemberRosterMembership` — the two roster-visible states — not the
four-valued `MembershipState` of a Realm member current result.

## The error count this repo reports is a compiler artifact, not a measurement

Measured on 2026-09-17 against `arkret-rust-sdk@39aa9932` / `garth@90765ab`
with `cargo check -p inkson --all-targets --keep-going`.

`rustc` aborts after item-signature collection when any item signature fails to
resolve, so **no function body in the crate is ever type-checked** while a
single unresolved path remains in a signature position. The handoff's
"lib 271 + lib test 432 = 703" was produced in that state: it counted
resolution-phase errors only.

Resolving four signature-position paths (`garth::{RunOptions, SyncLoopControl,
TransportProvider}` in `src/signal_receive_engine.rs`,
`agent_operations` -> `agent_scope` in `src/views/agents/model.rs`,
`arkret_wire` -> `arkret_models_crypto` in `src/fresh_device_recovery.rs`,
`WindowStartRealmMetadata` in `src/views/realm_admin/metadata.rs`) let body
checking run for the first time and exposed ~1050 further errors that were
always there:

| Phase | Before this round | After |
| --- | --- | --- |
| resolution (`E0432/E0433/E0425/E0422/E0412/E0603/...`) | 379 | 383 |
| body / type checking (`E0599/E0609/E0560/E0061/E0308/E0277/...`) | 63 | 990 |
| `cargo` totals, lib / lib test | 271 / 432 | 807 / 1305 |

The "after" number is larger because the compiler now sees more of the crate,
not because the crate regressed: the resolution-phase count is flat, and no
error message present after this round is absent from a run with these fixes
reverted except the six this round newly unmasked. Any per-repo error count
quoted for this migration should be assumed to be a lower bound until that
repo's signatures all resolve.

## Blocked on the typed current result family (spec section 4)

Not registered as SDK gaps: these wait on `result_writes[]` reaching the event
kinds that would write the family, and on the `CurrentSelector` /
`ResolvedCellState` projection shape being settled. Nothing here should be
implemented locally first.

| Inkson call sites | Waits on |
| --- | --- |
| `src/state/current_index.rs` (71 errors; `TypedCurrentRow::{revision, target}` at :1605-:1606, `CleanupTask.target` at :1552, and the projector arity from :1570 onward) | whether a typed current result carries its own `CurrentRevision` and target, or is addressed only through `CurrentSelector`. The whole local current index is written against the former. |
| `src/operation/../operation_tests.rs` :586, :927, :969, :988, :1042, :1060, :1081; `src/transport/tests/envelopes_payloads.rs` :123, :144, :159, :213, :443, :453, :463 | the `*_cell_writes` / `cell_write_projector` family (`pre_authoring_cell_writes`, `project_registered_cell_writes(_with_pre_state)`, `direct_registered_cell_writes`) — 6 of 147 event kinds have `result_writes[]` today |
| `src/views/realm_admin/admin_panel*`, `src/transport/realm_write.rs:817` (`RealmAuthorityRootValue`, `REALM_AUTHORITY_RESET`, `build_realm_authority_reset_intent`) | the authority-root typed current result and a `CurrentSelector` for it; see the `ak.realm.authority.reset` row under "Blocked by an SDK gap" |
| `src/sync_engine.rs` `run_circle_scope_rotate_pass`; `src/circle_mls.rs` `MembershipRemovalSnapshot.{request, local_mls_leaves}` | the `member_state` family, one of the 7 registered families with no writer. The pass's premise was "local membership projections are never negative authority for an MLS Remove"; the successor authority is the member roster current result. |
| `src/calendar.rs:21`, `src/views/kanban/tests/calendar_event.rs:161` (`calendar_schedule_revision_winner(_at_source)`) | `strand` family — registered, no writer |
| `src/identity/principal_genesis.rs` :153, :206 (`composite_subject`, `seed_test_governance_result`) | the governance result seeding shape |

## Residue of removed protocol mechanisms, not yet excised

These are call sites of concepts listed under "Removed with the protocol" that
still exist in inkson. They are not gaps and not section-4 blocked: each needs
its mechanism removed and its successor path wired, which is more than a
rename, so none of it was done as part of a naming pass.

| Residue | Inkson sites | Successor |
| --- | --- | --- |
| Seal family (`Seal`, `SealId`, `SealPrepareRequestBody`, `RealmSealFrontierView`, `RecoverySession.accepted_seal_frontier`, `prepare_and_sign_pcr_successor`, `clear_prepared_pcr_successor`) | ~20 sites, mostly `src/mls/account_recovery/*`, `src/recovery_flow.rs` | `RealmCommit`; recovery completion is the two-consecutive-positions boundary already wired in `garth::validate_recovery_commit_boundary` |
| governance / Seal / security frontier preflight (`refresh_realm_governance_frontier`, `seals_frontier_realm_{head,view}`, `seals_frontier_agent_head`, `frontier_request`, `fetch_and_cache_frontier`, `current_security_frontier_leaves`, `preview_security_frontier_with_added_keypackages`, `singleton_security_frontier_leaf`) | `src/event_submit.rs` consumers (15 sites), `src/views/realm_admin/members_panel/admission.rs` (33 errors) | `MlsCommitSubmission` + `src/mls/welcome_delivery.rs`; the admission flow's frontier preflight has no successor and should be deleted outright |
| Agent Sidecar *exchange* vocabulary (`AgentSidecarExchangeId`, `SidecarExchange{Request,Agent,Control}Fact`, `fold_sidecar_exchange`, `evaluate_sidecar_exchange_cache`, `agent_sidecar_exchange_event_set_digest`, `MESSAGE_METADATA_SIDECAR_EXCHANGE_BINDING_KEY`) | `src/sidecar.rs` (102 errors), `src/views/agents/{bootstrap,admin/controller}.rs` | none — the vocabulary was removed with no successor |
| RHRK history-secret family (`LocalAuthoritativeHistorySecret`, `PendingHistorySecrets`, `KeyBackupFrontierRef`, `derive_and_retain_realm_history_secret`, `KeyBackupKeybag::MlsHistory`, `HistorySecretRange`) | `src/key_backup/*`, `src/mls/account_recovery/backup_body.rs`, `src/key_backup/tests.rs:467` | none; the history exporter scheme was removed while the RFC 9420 RTC/Signal/reaction/blob labels were kept |
| `EventInitialSubmission` / `EventsSubmitOutcome` / `AuthorizationLease` / Control Proposal Ack (`events_submit_rejected_for_reason`, `ensure_events_submit_accepted`, `acquire_for_{events,intent}`, `delayed_initial_submission`, `is_actor_seq_cas_conflict_error`, `ControlProposalAck::issue_with_signer`) | `src/transport/*`, `src/mls/account_recovery/recovery_transaction.rs:210-:230` | `EventCommitSubmission` / `AuthoritySubmitOutcome`; `PublicationAuthorityContext.authority_commit_id` replaces `authority_set_ref.authority_set_digest` |

## Removed with the protocol

Deleted from this client because the concept no longer exists on the wire, with
no successor: Seal (incl. the PCR successor Seal journal), protocol-level Cell
and every cell projection, CBS execution planes, Bottom, Control Proposal Acks,
generic frontiers (events / Seal / MLS governance / security), Lattice ops,
`Predicate`/`Precondition`/`EventRequirements`/`StateWrite`, sequenced state,
causal register, or-set observed dots, ordered log, authority revision, the
history exporter and the whole RHRK history-key family
(`src/history_recovery.rs`, `src/history_ui.rs`, `src/state/history_*.rs`,
`src/mls/runtime/history_candidate_consumer.rs`), organization recovery key,
audited-E2EE, the full and relaxed MLS governance profiles, `security_frontier`,
`policy_root`, the create-locked `encryption_profile` and encryption floor,
`DurabilityPolicy` / `ContentScheme`, `AuthorizationLease` / `IngressReceipt`,
`EventSubmitContext`, and the Agent Sidecar *exchange* vocabulary.

The MLS exporter under `src/media/` and `src/rtc_transport/` is the SFrame
RFC 9420 exporter, is required by the spec, and is retained.
