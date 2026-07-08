//! Shared E2EE "Send Secure" pipeline.
//!
//! This module owns the MLS core + operation construction + commit/message
//! submission orchestration used by the Chat discussion view to send an
//! encrypted `ck.message.create`. It was extracted from the verified Chat
//! "Send Secure" strand so encryption, commit and persist-on-accept stay in one
//! path.
//!
//! Boundary: this module performs everything that MUST be identical across the
//! message-write path —
//!   1. MLS encrypt of the canonical Content Block bytes (`run_local_mls_encrypt` →
//!      `mls::runtime::encrypt_message_with_device_snapshot`),
//!   2. forced `ck.mls.commit` envelope build (governance binding / prev→post epoch / policy_root /
//!      membership_frontier),
//!   3. spec-canonical `ck.schema.encrypted_envelope.v1` wrap bound to the group-state ref,
//!   4. `ck.message.create` payload build (with reply-to + message id),
//!   5. submission ordering — commit FIRST (persist-on-accept snapshot + §7.10 history-backup
//!      schedule + move-submission record), then message.
//!
//! UI-shaped concerns stay in the caller: the optimistic bubble, draft
//! recovery, author-owned sidecar persistence, audit RYW receipt, and status
//! text. The caller drives these off the typed [`SecureSendBuild`] /
//! [`SecureSendOutcome`] returned here.

use dioxus::prelude::*;
use serde_json::json;

use crate::local_state::{LocalSealView, LocalStateStore, MoveSubmissionState};
use crate::operation::{OperationBuilder, sdk_event_local_operation_id, trim_realm_id, uuid_v7};

/// The structured MLS payload + the canonical AAD it was bound to.
pub(crate) type LocalEncryptedMessage = (
    cokret_sdk::EncryptedPayload,
    cokret_sdk::EncryptedEnvelopeAadV1,
);

/// Result of the local MLS encrypt step.
///
/// * `schedule_hash` — post-encrypt group key-schedule hash (B3d governance).
/// * `member_dids` — every principal DID in the group (B6c audit receipts).
/// * encrypted content — typed MLS payload + AAD, or `None` on failure.
/// * commit envelope — the SDK self-update commit, when the encrypt advanced the epoch (a forced
///   `ck.mls.commit` is then emitted).
/// * snapshot — post-commit snapshot, persisted by the caller ONLY after the server accepts the
///   `ck.mls.commit` (persist-on-accept).
pub(crate) type LocalMlsEncryptResult = (
    Option<cokret_sdk::Hash>,
    Vec<cokret_sdk::Did>,
    Option<LocalEncryptedMessage>,
    Option<cokret_sdk::MlsCommitEnvelope>,
    Option<crate::mls::persistence::MlsSnapshotEnvelope>,
);

/// Encrypt `plaintext_bytes` under the Realm MLS group and return the
/// structured MLS payload + the canonical AAD it was bound to, plus the
/// post-encrypt schedule hash, member DID set, optional self-update commit
/// envelope, and the post-commit snapshot to persist on accept.
///
/// Runs on wasm: the underlying `mls::runtime::encrypt_message_with_device_snapshot`
/// uses the same wasm-enabled OpenMLS path as kanban strand-content encryption.
///
/// On any failure (missing Welcome/snapshot, restore fails, encrypt fails) it
/// returns `(None, vec![], None, None, None)` and the caller aborts.
pub(crate) fn run_local_mls_encrypt(
    mut state_store: Signal<LocalStateStore>,
    realm_id: &str,
    principal_id: &str,
    device_id: &str,
    plaintext_bytes: &[u8],
) -> LocalMlsEncryptResult {
    let empty = (None, Vec::new(), None, None, None);
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let aad = cokret_sdk::EncryptedEnvelopeAadV1::hidden(realm_id, "ck.message.create");
    let Ok(aad_value) = serde_json::to_value(&aad) else {
        return empty;
    };
    let Ok((schedule_hash, member_dids, payload, commit_envelope, new_snapshot)) =
        crate::mls::runtime::encrypt_message_with_device_snapshot(
            &mut state_store.write(),
            secure_store.as_ref(),
            realm_id,
            principal_id,
            device_id,
            "application/vnd.cokret.message+json",
            aad_value,
            plaintext_bytes,
        )
    else {
        return empty;
    };
    (
        Some(schedule_hash),
        member_dids,
        Some((payload, aad)),
        commit_envelope,
        new_snapshot,
    )
}

/// Normalise a seal/state reference to a bare `sha256:<hex>` hash when it is
/// one (peeling `ck:seal:` / `ck:state:` prefixes), else `None`.
// Single canonical digest-grammar validator; moved to the MLS core layer
// (YGN-ARCH-01 step 2) and re-exported for this module's callers.
pub(crate) use crate::mls::group_events::mls_sha256_hash_from_ref;

/// Derive the base group-state ref (the MLS commit's `base_group_state_ref` /
/// the encrypted envelope's `group_state_ref` when no commit is forced) from
/// the Realm seal view, with a deterministic canonical-hash fallback.
pub(crate) fn mls_base_epoch_ref(seal_view: &LocalSealView, realm_id: &str) -> String {
    seal_view
        .frontier
        .iter()
        .chain(seal_view.leaves.iter())
        .chain(seal_view.state_root.iter())
        .find_map(|value| {
            if value.starts_with("ck:event:") && cokret_sdk::EventId::new(value.clone()).is_ok() {
                Some(value.clone())
            } else {
                mls_sha256_hash_from_ref(value)
            }
        })
        .unwrap_or_else(|| {
            crate::canonical::canonical_sha256(&json!({
                "kind": "chat_mls_base_epoch",
                "realm_id": realm_id,
                "epoch": seal_view.mls_epoch.unwrap_or(0),
            }))
            .unwrap_or_else(|_| {
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned()
            })
        })
}

/// Build the governance binding's `membership_frontier` for a self-update
/// Commit from the precise base MLS state it advances.
///
/// A self-update Commit does not consume invite/leave/ban/device-trust
/// proposals, so it must not claim arbitrary Seal frontier/leaves as
/// membership evidence. The base group state is the exact member set this
/// Commit carries forward.
pub(crate) fn mls_membership_frontier(
    base_group_state_ref: &str,
) -> Result<Vec<cokret_sdk::EventId>, String> {
    cokret_sdk::EventId::new(base_group_state_ref.to_owned())
        .map(|event_id| vec![event_id])
        .map_err(|_| {
            "MLS self-update membership_frontier requires a ck:event base group-state ref"
                .to_owned()
        })
}

/// Derive the governance binding's `policy_root` hash from the seal view's
/// `state_root`, with a deterministic canonical-hash fallback.
pub(crate) fn mls_policy_root(
    seal_view: &LocalSealView,
    realm_id: &str,
    schedule_hash: &cokret_sdk::Hash,
) -> Result<cokret_sdk::Hash, String> {
    let hash = seal_view
        .state_root
        .as_deref()
        .and_then(mls_sha256_hash_from_ref)
        .unwrap_or_else(|| {
            crate::canonical::canonical_sha256(&json!({
                "kind": "chat_mls_policy_root",
                "realm_id": realm_id,
                "frontier": seal_view.frontier,
                "state_root": seal_view.state_root,
                "schedule_hash": schedule_hash.as_str(),
            }))
            .unwrap_or_else(|_| {
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned()
            })
        });
    cokret_sdk::Hash::new(hash).map_err(|err| format!("invalid MLS policy root hash: {err:?}"))
}

/// The built (but not yet submitted) secure-send artifacts: the optional
/// forced MLS commit event, the encrypted `ck.message.create` event, and
/// the metadata the caller needs to drive UI / persist-on-accept.
pub(crate) struct SecureSendBuild {
    /// Forced `ck.mls.commit` to submit BEFORE the message, when the encrypt
    /// advanced the epoch. `None` rides the current epoch.
    pub commit_event: Option<cokret_sdk::Event>,
    /// The encrypted `ck.message.create` event.
    pub message_event: cokret_sdk::Event,
    /// Post-commit snapshot — persisted by the caller ONLY after the server
    /// accepts the commit (persist-on-accept).
    pub new_mls_snapshot: Option<crate::mls::persistence::MlsSnapshotEnvelope>,
    /// Every principal DID in the post-encrypt group (audit RYW delivered set).
    pub member_dids: Vec<cokret_sdk::Did>,
    /// The Realm move-seal ref captured at build time (covered-seals binding).
    pub seal_ref: String,
}

/// Build the full encrypted send (MLS encrypt → forced commit event →
/// `ck.schema.encrypted_envelope.v1` wrap → `ck.message.create` payload) for a
/// discussion message.
///
/// Honest fail-closed: returns `Err(msg)` whenever the MLS group cannot be
/// loaded / encrypted / committed for this Realm. The caller MUST surface the
/// message and abort — never fall back to a plaintext or fake send.
///
/// `seal_view` is the caller-captured `seal_view_for_realm(realm_id)` snapshot;
/// passing it in keeps the (synchronous) `state_store` read at the call site.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_secure_send(
    state_store: Signal<LocalStateStore>,
    seal_view: &LocalSealView,
    realm_id: &str,
    actor: &str,
    device_id: &str,
    strand_id: &str,
    message_id: &str,
    reply_to: Option<&str>,
    plaintext_bytes: &[u8],
    expiry: Option<cokret_sdk::DisappearingMessageExpiry>,
) -> Result<SecureSendBuild, String> {
    let seal_ref = seal_view.move_seal_ref();
    let (
        local_schedule_hash,
        local_member_dids,
        encrypted_message,
        real_commit_envelope,
        new_mls_snapshot,
    ): LocalMlsEncryptResult =
        run_local_mls_encrypt(state_store, realm_id, actor, device_id, plaintext_bytes);

    let Some((encrypted_payload, envelope_aad)) = encrypted_message else {
        return Err("Send Secure could not produce an MLS encrypted payload".to_owned());
    };
    let Some(local_schedule_hash) = local_schedule_hash else {
        return Err("Send Secure could not derive the MLS key schedule hash".to_owned());
    };
    if local_member_dids.is_empty() {
        return Err("Send Secure could not resolve MLS group members".to_owned());
    }

    let base_group_state_ref = mls_base_epoch_ref(seal_view, realm_id);
    let (group_state_ref, commit_envelope) =
        if let Some(real_commit_envelope) = real_commit_envelope.as_ref() {
            let mls_commit_epoch = real_commit_envelope.epoch;
            // base_epoch MUST be the SDK group's PRE-commit epoch so
            // next_epoch == base_epoch + 1 holds by construction.
            // `real_commit_envelope.epoch` is the POST-commit epoch.
            let prev_epoch = mls_commit_epoch.saturating_sub(1);
            let commit_event_id = format!("ck:event:{}", uuid_v7());
            let commit_event_id_typed = cokret_sdk::EventId::new(commit_event_id.clone())
                .map_err(|err| format!("MLS commit event id invalid: {err:?}"))?;
            let realm_id_typed = cokret_sdk::RealmId::new(trim_realm_id(realm_id))
                .map_err(|err| format!("MLS commit Realm id invalid: {err:?}"))?;
            // Reuse the genesis-locked `policy_root` (soland carries it forward
            // unchanged and rejects a drifted binding with
            // `governance_binding_mismatch`); only fall back to the Seal-derived
            // root for groups created before it was tracked. See
            // `mls_encrypt::kanban_mls_commit_policy_root`.
            let policy_root = match state_store
                .read()
                .genesis_policy_root_for_effective_scope(realm_id, None)
            {
                Some(stored) => cokret_sdk::Hash::new(stored)
                    .map_err(|err| format!("stored MLS genesis policy_root invalid: {err:?}"))?,
                None => mls_policy_root(seal_view, realm_id, &local_schedule_hash)?,
            };
            let governance_binding = cokret_sdk::MlsGovernanceBindingPayload::realm(
                realm_id_typed,
                real_commit_envelope.group_id.clone(),
                prev_epoch,
                mls_commit_epoch,
                mls_membership_frontier(&base_group_state_ref)?,
                policy_root,
                cokret_sdk::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
                cokret_sdk::CORE_REDUCER_PROFILE,
            )
            .map_err(|err| format!("MLS governance binding failed: {err}"))?;
            let mls_commit_payload = cokret_sdk::MlsCommitPayload::new(
                real_commit_envelope.group_id.clone(),
                prev_epoch,
                base_group_state_ref.clone(),
                Vec::new(),
                mls_commit_epoch,
                real_commit_envelope.commit_digest.clone(),
                governance_binding,
            )
            .map_err(|err| format!("MLS commit payload failed: {err}"))?;
            // Spec-canonical write path: ck.mls.commit event via ck.events.submit.
            let commit_builder = crate::operation::ck_ops::mls_commit_with_governance(
                realm_id,
                actor,
                &mls_commit_payload,
            )
            .map_err(|err| format!("MLS commit payload failed: {err}"))?;
            let mut commit_event = commit_builder
                .build_sdk_event("inkson")
                .map_err(|err| format!("MLS commit SDK Event conversion failed: {err}"))?;
            commit_event.event_id = commit_event_id_typed;
            (commit_event_id, Some(commit_event))
        } else {
            (base_group_state_ref, None)
        };

    // Wrap the MLS payload in the spec-canonical
    // `ck.schema.encrypted_envelope.v1` wire shape, binding
    // key_ref.group_state_ref to the current MLS group state.
    let encrypted_envelope = cokret_sdk::EncryptedEnvelopeV1::from_payload(
        &encrypted_payload,
        envelope_aad,
        cokret_sdk::AadVisibility::Hidden,
        &group_state_ref,
    )
    .map_err(|err| format!("MLS encrypted envelope build failed: {err}"))?;
    let encrypted_payload_json = serde_json::to_value(&encrypted_envelope)
        .map_err(|err| format!("MLS encrypted envelope encode failed: {err}"))?;
    let typed_strand_id = cokret_sdk::StrandId::new(strand_id.to_owned())
        .map_err(|err| format!("Send Secure strand id invalid: {err:?}"))?;
    let mut message_payload = cokret_sdk::MessageCreatePayload::with_encrypted_content(
        typed_strand_id,
        "discussion",
        encrypted_payload_json,
    )
    .with_message_id(message_id.to_owned());
    if let Some(reply_to) = reply_to.filter(|value| !value.trim().is_empty()) {
        message_payload = message_payload.with_reply_to(reply_to);
    }
    if let Some(expiry) = expiry {
        message_payload = message_payload.with_expiry(expiry);
    }
    let msg_payload_value = message_payload
        .to_value()
        .map_err(|err| format!("Send Secure payload encode failed: {err}"))?;
    let message_envelope = OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::MessageCreate,
    )
    .body(msg_payload_value)
    .build_sdk_event("inkson");

    let commit_event = commit_envelope;
    let message_event = message_envelope
        .map_err(|err| format!("Send Secure SDK Event conversion failed: {err}"))?;

    Ok(SecureSendBuild {
        commit_event,
        message_event,
        new_mls_snapshot,
        member_dids: local_member_dids,
        seal_ref,
    })
}

/// The result of submitting a [`SecureSendBuild`]: either the server-accepted
/// message event id (commit, if any, already accepted + snapshot persisted) or
/// a categorised failure the caller renders into its own UI.
pub(crate) enum SecureSendOutcome {
    /// Message accepted; `event_id` is the server's `ck.message.create` id.
    Sent { event_id: String, status: String },
    /// The forced MLS commit was rejected; message NOT submitted. Snapshot was
    /// NOT advanced (the next retry uses the correct `expected_prev_epoch`).
    CommitFailed { message: String },
    /// The `ck.message.create` submission failed (commit, if any, accepted).
    MessageFailed { message: String },
}

/// Submit a built secure send: forced `ck.mls.commit` first (persist-on-accept
/// snapshot + §7.10 history-backup schedule + move-submission record), then the
/// encrypted `ck.message.create`. The MLS core ordering + persistence here is
/// shared verbatim by the chat write path.
///
/// The caller owns all UI reconciliation: it inspects [`SecureSendOutcome`] to
/// clear/fail the optimistic bubble, persist the author sidecar, restore the
/// draft, and emit any audit receipt.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn submit_secure_send(
    api: &crate::api::CokretApi,
    mut state_store: Signal<LocalStateStore>,
    build: SecureSendBuild,
    realm_id: &str,
    device_id: &str,
    base_url: String,
    api_token: String,
    actor: String,
) -> SecureSendOutcome {
    let SecureSendBuild {
        commit_event,
        message_event,
        new_mls_snapshot,
        seal_ref,
        member_dids: _,
    } = build;
    let commit_op_id = commit_event
        .as_ref()
        .map(|commit| sdk_event_local_operation_id(commit).to_owned());

    if let Some(commit_event) = commit_event {
        // Submit the forced MLS commit first; if it fails, abort the message
        // send (covered_seals won't bind).
        match match api.event_submitter() {
            Ok(sub) => sub.submit_sdk_event(&commit_event).await,
            Err(err) => Err(err),
        } {
            Ok(resp) => {
                // X14 — persist-on-accept: the server accepted the commit, so
                // NOW advance the local snapshot to the post-commit epoch. On a
                // commit reject we skip this and the snapshot stays at the
                // pre-commit epoch, so the next Send Secure retries at the
                // correct `expected_prev_epoch` instead of skewing forever.
                if let Some(snapshot) = new_mls_snapshot {
                    state_store
                        .write()
                        .save_mls_snapshot(realm_id.to_owned(), snapshot);
                    // §7.10 continuous backup: the commit advanced the epoch,
                    // so re-upload this Realm's mls_history series tail
                    // (debounced; no-op until the 24-word Recovery Key exists).
                    crate::components::schedule_mls_history_backup_after_commit(
                        base_url.clone(),
                        api_token.clone(),
                        actor.clone(),
                        device_id.to_owned(),
                        realm_id.to_owned(),
                        state_store,
                    );
                }
                if let Some(commit_op_id) = commit_op_id {
                    state_store.write().record_move_submission_with_event_id(
                        commit_op_id,
                        Some(resp.event_id.clone()),
                        realm_id.to_owned(),
                        "mls_commit".to_owned(),
                        MoveSubmissionState::from_submit_state("accepted", None),
                        None,
                        Some(seal_ref.clone()),
                    );
                }
            }
            Err(err) => {
                return SecureSendOutcome::CommitFailed {
                    message: format!("MLS commit event submit failed: {err}"),
                };
            }
        }
    }

    match match api.event_submitter() {
        Ok(sub) => sub.submit_sdk_event(&message_event).await,
        Err(err) => Err(err),
    } {
        Ok(resp) => SecureSendOutcome::Sent {
            event_id: resp.event_id,
            status: resp.status,
        },
        Err(err) => SecureSendOutcome::MessageFailed {
            message: format!("Message send failed: {err}"),
        },
    }
}
