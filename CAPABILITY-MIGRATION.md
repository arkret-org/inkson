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
| Current state | `ak:cell:*` current results | `RealmStateSnapshot.current_state_entries` — `TypedCurrentResult` keyed by `CurrentSelector` with a `CurrentRevision{commit_id, stream_position}` |
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
| Current-state projection | `src/current_projection.rs` over `TypedCurrentResult` / `CurrentSelector`, incl. `scope_has_accepted_mls_genesis` | `src/local_state_tests/projections.rs` |
| Chat, Direct Conversation, reactions, polls, read receipts, mentions | `src/views/chat/`, `src/messaging/`, `src/state/direct_conversation.rs` | `src/views/chat/tests/`, `tests/e2e/inkson.strands.chat-discussion.spec.ts` |
| Circle, Realm, Space, Strand, Kanban, calendar | `src/circle.rs`, `src/circle_mls.rs`, `src/realm_tree.rs`, `src/views/kanban/`, `src/calendar.rs` | `src/views/kanban/tests/`, `tests/e2e/inkson.strands.kanban.spec.ts` |
| File transfer, media / WebRTC (SFrame RFC 9420 exporter), push | `src/file_transfer.rs`, `src/media/`, `src/rtc_transport/`, `src/push/` | `src/push/tests.rs`, `tests/cross_platform/push_*.spec.ts` |
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
| `ProofSummary` | `recovery-session.schema.json#/$defs/proof_summary` | recovery session proof summary |
| `RecoveryPolicyPublishRequest` | `recovery-policy.schema.json#/$defs/recovery_policy_publish_request` | recovery policy publish |

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
