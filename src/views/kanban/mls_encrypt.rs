use arkret_wire::event_kind_str;
use serde_json::{Value, json};

use super::model::*;
use super::{
    apply_card_detail_draft, card_detail_update_patch, collect_encryptable_private_patch_values,
    kanban_plaintext_block_reason, replace_private_patch_values,
};
// YGN-ARCH-01 step 2: the MLS commit/genesis event construction moved to
// `crate::mls::group_events` (it serves any effective scope and is consumed
// by `mls::admission` / `circle_mls` / `sync_engine`, not just kanban).
use crate::mls::group_events::{build_creator_mls_genesis_event, mls_commit_event_from_store};
use crate::state::{LocalStateStore, MoveSubmissionState};
use crate::transport::auth::with_authed_api;
use crate::views::helpers::short_protocol_id;

/// The MLS events an encrypted write must submit, in submit order: the
/// one-time `ak.mls.genesis` (if not yet emitted) MUST precede any forced
/// `ak.mls.commit` so the server has the group at epoch 0 before the commit
/// bumps it.
#[derive(Default, Debug)]
pub(super) struct EncryptedWriteMlsEvents {
    pub genesis: Option<crate::operation::LocalOperation>,
    /// Exact public epoch-0 bytes whose content-addressed refs are carried by
    /// `genesis`. Uploaded before the Event is submitted.
    pub genesis_material: Option<crate::mls::runtime::InitialMlsSnapshotSummary>,
    pub commit: Option<crate::operation::LocalOperation>,
    /// X14 — the post-commit MLS snapshot. Persisted by the caller ONLY
    /// after the server ACCEPTS `commit`, so the local snapshot epoch never
    /// races ahead of the server's accepted epoch (the root cause of
    /// permanent `mls_epoch_skew`). `None` when the encrypted write rides the
    /// current epoch without forcing a commit.
    pub snapshot: Option<crate::mls::persistence::MlsSnapshotEnvelope>,
    /// Must commit before genesis/commit/content submission begins.
    pub pending_history_secrets: Option<crate::state::PendingHistorySecrets>,
}

/// An encrypted patch whose envelopes still need the epoch's group-state
/// reference.
///
/// The reference is the `event_id` of the Event that established the epoch — the
/// `ak.mls.commit` this same write carries, or the `ak.mls.genesis` for epoch 0 —
/// so it does not exist until that Event is authored. Keeping the patch unsealed
/// until then is what makes the reference correct instead of a draft value that
/// a later pass has to rewrite.
#[derive(Debug)]
pub(super) struct EncryptedPatchPlan {
    patch: Value,
    paths: Vec<String>,
    payloads: Vec<Value>,
    group_id: String,
    epoch: u64,
    accepted_group_state_ref: Option<String>,
}

impl EncryptedPatchPlan {
    /// A plaintext write: nothing to seal.
    fn plaintext(patch: Value) -> Self {
        Self {
            patch,
            paths: Vec::new(),
            payloads: Vec::new(),
            group_id: String::new(),
            epoch: 0,
            accepted_group_state_ref: Some(String::new()),
        }
    }

    pub(super) fn is_plaintext(&self) -> bool {
        self.payloads.is_empty()
    }

    /// The reference this plan needs, given the Events this write authored.
    pub(super) fn resolve_group_state_ref(
        &self,
        commit: Option<&arkret_sdk::EventId>,
        genesis: Option<&arkret_sdk::EventId>,
    ) -> Result<String, String> {
        if let Some(accepted) = self.accepted_group_state_ref.as_ref() {
            return Ok(accepted.clone());
        }
        if let Some(commit) = commit {
            return Ok(commit.to_string());
        }
        if self.epoch == 0
            && let Some(genesis) = genesis
        {
            return Ok(genesis.to_string());
        }
        Err("encrypted write has no accepted group-state reference for its epoch".to_owned())
    }

    /// Seal every envelope against the accepted epoch reference.
    pub(super) fn seal(
        self,
        commit: Option<&arkret_sdk::EventId>,
        genesis: Option<&arkret_sdk::EventId>,
    ) -> Result<Value, String> {
        if self.is_plaintext() {
            return Ok(self.patch);
        }
        let group_state_ref = self.resolve_group_state_ref(commit, genesis)?;
        let group_state_ref = arkret_sdk::EventId::new(group_state_ref)
            .map_err(|error| format!("invalid patch group-state Event id: {error}"))?;
        let mut sealed = Vec::with_capacity(self.payloads.len());
        for value in &self.payloads {
            let payload = serde_json::from_value::<arkret_sdk::EncryptedPayload>(value.clone())
                .map_err(|error| format!("invalid encrypted patch payload: {error}"))?;
            if payload.group_id != self.group_id || payload.epoch != self.epoch {
                return Err(
                    "encrypted patch values do not share one MLS group and epoch".to_owned(),
                );
            }
            if payload.pre_encryption_header.group_state_ref != group_state_ref {
                return Err(
                    "encrypted patch group-state reference changed after sealing".to_owned(),
                );
            }
            let envelope = arkret_sdk::mls::encrypted_envelope_from_payload(&payload)
                .map_err(|error| format!("build encrypted Strand patch envelope: {error}"))?;
            sealed.push(
                serde_json::to_value(envelope).map_err(|error| {
                    format!("serialize encrypted Strand patch envelope: {error}")
                })?,
            );
        }
        let mut patch = self.patch;
        replace_private_patch_values(&mut patch, &self.paths, sealed)?;
        Ok(patch)
    }
}

#[derive(Clone, Debug)]
pub(super) struct SidecarTrackWriteContext {
    pub binding: Option<arkret_sdk::SidecarMlsBinding>,
    pub ready: bool,
}

fn active_scope_matches_write_identity(
    scope: &crate::secure_key_store::ActiveDeviceSeedScope,
    actor_id: &str,
    device_id: &str,
) -> bool {
    crate::mls_api_helpers::principal_core_id(actor_id).is_ok_and(|actor_core| {
        scope.authority.principal_id == actor_core && scope.device_id.as_str() == device_id
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn encrypt_private_card_detail_patch_values_for_effective_scope(
    patch: Value,
    realm_id: &str,
    strand_id: &str,
    actor_id: &str,
    device_id: &str,
    mut state_store: SyncSignal<LocalStateStore>,
    sidecar: Option<&SidecarTrackWriteContext>,
) -> Result<(EncryptedPatchPlan, EncryptedWriteMlsEvents), String> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let mut store = state_store.write();
    encrypt_private_card_detail_patch_values_with_store_for_effective_scope(
        patch,
        realm_id,
        strand_id,
        actor_id,
        device_id,
        &mut store,
        secure_store.as_ref(),
        sidecar,
    )
}

#[cfg(test)]
pub(super) fn encrypt_private_card_detail_patch_values_with_store(
    patch: Value,
    realm_id: &str,
    strand_id: &str,
    actor_id: &str,
    device_id: &str,
    state_store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Result<(EncryptedPatchPlan, EncryptedWriteMlsEvents), String> {
    encrypt_private_card_detail_patch_values_with_store_for_effective_scope(
        patch,
        realm_id,
        strand_id,
        actor_id,
        device_id,
        state_store,
        secure_store,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn encrypt_private_card_detail_patch_values_with_store_for_effective_scope(
    patch: Value,
    realm_id: &str,
    strand_id: &str,
    actor_id: &str,
    device_id: &str,
    state_store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    sidecar: Option<&SidecarTrackWriteContext>,
) -> Result<(EncryptedPatchPlan, EncryptedWriteMlsEvents), String> {
    let account_scope = crate::secure_key_store::active_device_seed_scope()
        .ok_or_else(|| "active account authority is unavailable".to_owned())?;
    if !active_scope_matches_write_identity(&account_scope, actor_id, device_id) {
        return Err("encrypted write identity does not match the active account".to_owned());
    }
    let authority = &account_scope.authority;
    let account_device_id = &account_scope.device_id;
    if let Some(sidecar) = sidecar
        && (!sidecar.ready || sidecar.binding.is_none())
    {
        return Err("Private Sidecar MLS access is not ready".to_owned());
    }
    if let Some(binding) = sidecar.and_then(|sidecar| sidecar.binding.as_ref()) {
        binding
            .validate()
            .map_err(|error| format!("Private Sidecar MLS binding is invalid: {error}"))?;
    }
    let values = collect_encryptable_private_patch_values(&patch)?;
    if values.is_empty() {
        return Ok((
            EncryptedPatchPlan::plaintext(patch),
            EncryptedWriteMlsEvents::default(),
        ));
    }
    let plaintext_values = values
        .iter()
        .map(|(_, bytes)| bytes.clone())
        .collect::<Vec<_>>();
    let sidecar_binding = sidecar.and_then(|context| context.binding.as_ref());
    let effective_scope = match sidecar_binding {
        Some(binding) => arkret_sdk::ScopeRef::Sidecar {
            realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())
                .map_err(|error| format!("invalid Sidecar Realm id: {error}"))?,
            sidecar_id: binding.sidecar_id.clone(),
        },
        None => arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())
                .map_err(|error| format!("invalid Realm id: {error}"))?,
        },
    };
    let mut fresh_summary = if sidecar_binding.is_none() {
        let snapshot = state_store
            .mls_snapshot_for_scope(&effective_scope)
            .ok_or_else(|| "checkpoint-proven MLS group state is pending".to_owned())?;
        state_store.mls_group_state_ref_for_scope(
            &effective_scope,
            snapshot.group_id.as_str(),
            snapshot.epoch,
        )?;
        None
    } else {
        if state_store
            .mls_snapshot_for_scope(&effective_scope)
            .is_none()
        {
            return Err("Private Sidecar MLS snapshot is unavailable".to_owned());
        }
        None
    };
    // Realm creation persists the creator's epoch-0 snapshot before submitting
    // `ak.mls.genesis`. If that submit was interrupted or an older client left
    // only the emitted flag, this write is not a fresh-snapshot path, but it
    // still has all material needed to rebuild genesis. Recover the summary so
    // the dispatch path can submit (or duplicate-resolve) genesis before the
    // encrypted Strand update instead of failing on a missing group_state_ref.
    if sidecar_binding.is_none()
        && fresh_summary.is_none()
        && crate::mls::creator_bootstrap::creator_mls_bootstrap_pending(
            state_store,
            realm_id,
            actor_id,
        )
    {
        fresh_summary = crate::mls::runtime::initial_mls_snapshot_summary_from_existing(
            state_store,
            secure_store,
            realm_id,
            authority,
            account_device_id,
        )
        .map_err(|error| error.user_message())?;
    }
    // Build genesis BEFORE the first commit mutates the group past epoch 0.
    let genesis_event = if let Some(sidecar) = sidecar {
        crate::mls::group_events::build_creator_mls_genesis_event_for_effective_scope_with_binding(
            state_store,
            realm_id,
            None,
            actor_id,
            fresh_summary.as_ref(),
            sidecar.binding.clone(),
        )?
    } else {
        build_creator_mls_genesis_event(state_store, realm_id, actor_id, fresh_summary.as_ref())?
    };
    let snapshot = state_store
        .mls_snapshot_for_scope(&effective_scope)
        .ok_or_else(|| "MLS snapshot is unavailable after bootstrap".to_owned())?;
    let accepted_group_state_ref = state_store
        .mls_group_state_ref_for_scope(&effective_scope, &snapshot.group_id, snapshot.epoch)
        .map_err(|_| {
            "MLS group-state Event must be accepted before encrypting a Strand update".to_owned()
        })?;
    let (
        schedule_hash,
        _member_ids,
        encrypted_values,
        prepared_commit,
        new_snapshot,
        pending_history_secrets,
    ) = crate::mls::runtime::encrypt_values_with_device_snapshot_for_effective_scope(
        state_store,
        secure_store,
        realm_id,
        authority,
        account_device_id,
        KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
        &plaintext_values,
        event_kind_str::STRAND_UPDATE,
        accepted_group_state_ref.clone(),
        None,
        sidecar_binding,
    )
    .map_err(|err| err.user_message())?;
    let commit_event = match prepared_commit.as_ref() {
        Some(prepared_commit) => Some(if let Some(sidecar) = sidecar {
            crate::mls::group_events::mls_commit_event_from_store_for_sidecar_scope(
                state_store,
                realm_id,
                actor_id,
                &prepared_commit.envelope,
                &prepared_commit.previous_governance_binding,
                sidecar.binding.clone().ok_or_else(|| {
                    "Private Sidecar MLS governance binding is unavailable".to_owned()
                })?,
            )?
        } else {
            mls_commit_event_from_store(
                state_store,
                realm_id,
                actor_id,
                &schedule_hash,
                &prepared_commit.envelope,
                &prepared_commit.previous_governance_binding,
            )?
        }),
        None => None,
    };
    let first_payload = encrypted_values
        .first()
        .cloned()
        .ok_or_else(|| "MLS encryption returned no encrypted patch values".to_owned())
        .and_then(|value| {
            serde_json::from_value::<arkret_sdk::EncryptedPayload>(value)
                .map_err(|error| format!("invalid encrypted patch payload: {error}"))
        })?;
    let accepted_group_state_ref = Some(accepted_group_state_ref.to_string());
    // X5.1 — encryption succeeded. Persist the author's own plaintext into
    // the local-only sidecar so a later re-projection (refresh / board
    // switch / live poll) can render the author's own content, which can
    // never be recovered by decrypting the author's own MLS ciphertext.
    // The stored value is the JSON-serialized patch *value* (the same
    // `plaintext_values` bytes that were just encrypted) as a UTF-8 string;
    // the read path parses it back with `serde_json::from_str` and feeds it
    // to `strand_body_display_text`, keeping write+read symmetric. This is
    // local-only and NEVER enters the op / `append_raw_operation` payload.
    //
    // Key the sidecar by the path the ENCRYPTED value lands on
    // (`content` -> `encrypted_content`), because that is the path the reader
    // resolves the envelope at; writer and reader must agree on one token.
    for (path, plaintext_bytes) in &values {
        if let Ok(plaintext_str) = std::str::from_utf8(plaintext_bytes) {
            state_store.save_private_plaintext(
                realm_id,
                strand_id,
                kanban_encrypted_patch_path(path),
                plaintext_str,
            );
        }
    }
    let paths = values.into_iter().map(|(path, _)| path).collect::<Vec<_>>();
    Ok((
        EncryptedPatchPlan {
            patch,
            paths,
            payloads: encrypted_values,
            group_id: first_payload.group_id.clone(),
            epoch: first_payload.epoch,
            accepted_group_state_ref,
        },
        EncryptedWriteMlsEvents {
            genesis: genesis_event,
            genesis_material: fresh_summary,
            commit: commit_event,
            // X14 — forced-commit snapshots are persisted by
            // `dispatch_card_detail_update` ONLY after the server accepts the
            // commit (see the commit Ok arm). Ordinary application writes
            // already persisted the same-epoch ratchet snapshot in-place.
            snapshot: new_snapshot,
            pending_history_secrets,
        },
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch_card_detail_update(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    device_id: String,
    current: KanbanCard,
    draft: CardDetailDraft,
    // R4: three-state security signal (see `kanban_plaintext_block_reason`).
    scope_security_encrypted: Option<bool>,
    sidecar_track_write: Option<SidecarTrackWriteContext>,
    synthesis_entry_id: Option<String>,
    synthesis_revision_body: Option<String>,
    mut selected_card: Signal<Option<KanbanCard>>,
    mut state_store: SyncSignal<LocalStateStore>,
    mut board_status: Signal<String>,
) -> bool {
    let mut current = current;
    if arkret_sdk::StrandId::new(current.id.clone()).is_err() {
        let canonical_id = {
            let snapshot = state_store.read().load();
            event_derived_target_aliases(&snapshot.raw_operations)
                .get(&current.id)
                .cloned()
        };
        let Some(canonical_id) = canonical_id else {
            board_status
                .set("card creation is still awaiting its canonical Strand identity".to_owned());
            return false;
        };
        current.id = canonical_id;
    }
    let patch = match card_detail_update_patch(&current, &draft) {
        Ok(patch) => patch,
        Err(msg) => {
            board_status.set(msg);
            return false;
        }
    };
    // R4 fail-closed: when the Realm security state is unknown (`None`),
    // treat the scope as encrypted so we take the encrypt path rather than
    // emitting a plaintext patch. The plaintext-block guard below still
    // fails closed on the unknown state for any private content.
    let effective_security_encrypted = current
        .security_encrypted
        .unwrap_or_else(|| scope_security_encrypted.unwrap_or(true));
    let calendar_changed = patch
        .as_object()
        .is_some_and(|entries| entries.contains_key(CALENDAR_SUBTREE_PATH));
    let (patch_plan, mls_events) = if effective_security_encrypted {
        match encrypt_private_card_detail_patch_values_for_effective_scope(
            patch,
            &realm_id,
            &current.id,
            &actor_id,
            &device_id,
            state_store,
            sidecar_track_write.as_ref(),
        ) {
            Ok(result) => result,
            Err(msg) => {
                board_status.set(msg);
                return false;
            }
        }
    } else {
        (
            EncryptedPatchPlan::plaintext(patch),
            EncryptedWriteMlsEvents::default(),
        )
    };
    let EncryptedWriteMlsEvents {
        genesis: mls_genesis_op,
        genesis_material: mls_genesis_material,
        commit: mls_commit_op,
        snapshot: _mls_new_snapshot,
        pending_history_secrets,
    } = mls_events;

    let sidecar_effective_scope = match sidecar_track_write
        .as_ref()
        .and_then(|context| context.binding.as_ref())
    {
        Some(binding) => {
            let realm_id = match arkret_sdk::RealmId::new(realm_id.clone()) {
                Ok(realm_id) => realm_id,
                Err(error) => {
                    board_status.set(format!("invalid Sidecar Realm id: {error}"));
                    return false;
                }
            };
            Some(arkret_sdk::ScopeRef::Sidecar {
                realm_id,
                sidecar_id: binding.sidecar_id.clone(),
            })
        }
        None => None,
    };
    // R4: feed the guard the three-state security signal. An explicit
    // per-card `security_encrypted` flag (`Some`) wins; otherwise fall back to
    // the scope three-state so an unknown projection fails closed.
    let guard_security_state = current
        .security_encrypted
        .map(Some)
        .unwrap_or(scope_security_encrypted);

    // Optimistic detail-panel feedback: apply the draft to the open card.
    // The board itself re-renders from the appended `ak.strand.update` op
    // below — `columns` is a `use_memo` over `raw_operations`, folded by
    // `overlay_local_card_update_records`, so there is no direct signal write.
    let mut updated_card = current.clone();
    apply_card_detail_draft(&mut updated_card, &draft);
    if sidecar_track_write.is_none() {
        selected_card.set(Some(updated_card));
    }

    // The holder-local identity of this write. It is allocated before the Event
    // exists, which is exactly why the optimistic row can be keyed by it: the
    // Event id is only known after the epoch's Event has been authored.
    let local_operation_id = crate::operation::LocalOperationId::new();
    let operation_id = local_operation_id.to_string();
    let synthesis_entry_id = synthesis_revision_body
        .as_ref()
        .map(|_| synthesis_entry_id.unwrap_or_else(|| operation_id.clone()));
    let local_synthesis_revision_body = synthesis_revision_body
        .clone()
        .filter(|_| !effective_security_encrypted);
    let kind = event_kind_str::STRAND_UPDATE.to_owned();
    state_store.write().enqueue_local_projection_command(
        operation_id.clone(),
        Some(realm_id.clone()),
        json!({
            "kind": kind,
            "operation_id": operation_id.clone(),
            "actor_id": actor_id.clone(),
            "created_at": arkret_sdk::canonical::format_timestamp_canonical(
                crate::clock::now_utc_millis(),
            ),
            "write_state": "queued",
            "synthesis_entry_id": synthesis_entry_id,
            "synthesis_revision_body": local_synthesis_revision_body,
            "encrypted_payload_local": effective_security_encrypted,
        }),
    );
    board_status.set(format!(
        "submitting {kind} operation {}",
        short_protocol_id(&operation_id)
    ));
    let api_token = token();
    let mls_commit_operation_id = mls_commit_op
        .as_ref()
        .map(|op| op.local_operation_id().to_string());
    // X11.2 — first-write trigger. Read the context-provided
    // `needs_mls_backup` signal HERE (inside the Dioxus scope), so the
    // encrypted-write success arm can flip the backup prompt on directly,
    // bypassing the fragile boot detection effect. Best-effort: `None` when
    // no provider is mounted (unit tests / non-app callers).
    let backup_trigger_signal = crate::components::try_needs_mls_backup_signal();
    let base_for_backup_trigger = base_url.clone();
    let actor_for_backup_trigger = actor_id.clone();
    let backup_account_scope = if effective_security_encrypted {
        match crate::secure_key_store::active_device_seed_scope() {
            Some(scope) if active_scope_matches_write_identity(&scope, &actor_id, &device_id) => {
                Some(scope)
            }
            Some(_) => {
                board_status.set("active account authority does not match card author".to_owned());
                return false;
            }
            None => {
                board_status.set("active account authority is unavailable".to_owned());
                return false;
            }
        }
    } else {
        None
    };
    let sidecar_effective_scope = sidecar_effective_scope.clone();
    let calendar_basis_refs = current.calendar_schedule_basis_refs();
    let update_realm_id = realm_id.clone();
    let update_actor_id = actor_id.clone();
    let update_strand_id = current.id.clone();
    let submit_authority = match crate::app::SessionContext::get()
        .active_account
        .read()
        .as_ref()
        .map(|account| account.authority.clone())
    {
        Some(authority) => authority,
        None => {
            board_status.set("active account authority is unavailable".to_owned());
            return false;
        }
    };
    // Saving closes the editor immediately. A component-scoped task would be
    // cancelled as that edit subtree unmounts, leaving the durable operation
    // permanently queued and never sending its Event. Run the protocol
    // sequence at the root and retain only the app-owned state store across
    // awaits; component UI signals are deliberately not captured.
    let submit_state_store = crate::app::runtime_adapter::state_store_handle(state_store);
    dioxus::core::spawn_forever(async move {
        if let Some(pending) = pending_history_secrets {
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            if let Err(error) = pending.persist(secure_store.as_ref()).await {
                submit_state_store.write(|store| {
                    store.update_raw_operation_write_state(
                        &operation_id,
                        "failed",
                        None,
                        Some(error.to_string()),
                    );
                });
                tracing::warn!(%error, "MLS history-secret persist failed");
                return;
            }
            submit_state_store.write(|store| store.publish_history_secrets(pending));
        }
        // Genesis MUST land before the first commit so the server has the
        // group at epoch 0 before the commit bumps it to 1. A duplicate
        // genesis is success only after resolving the exact already-accepted
        // Event id; merely setting the emitted flag strands secure messages
        // without their mandatory group_state_ref.
        let mut accepted_genesis_event_id = None::<arkret_sdk::EventId>;
        if let Some(genesis_op) = mls_genesis_op {
            let realm_for_genesis_lookup = realm_id.clone();
            let genesis_state_store = submit_state_store.clone();
            let genesis_authority = submit_authority.clone();
            let genesis_result = with_authed_api(&base_url, api_token.clone(), |api| async move {
                let material = mls_genesis_material.ok_or_else(|| {
                    anyhow::anyhow!(
                        "ak.mls.genesis is missing its public group-state upload material"
                    )
                })?;
                crate::mls::runtime::upload_mls_genesis_public_material(&api, &material)
                    .await
                    .map_err(|error| anyhow::anyhow!(error.user_message()))?;
                let submitter = api
                    .event_submitter()?
                    .with_state_store(genesis_state_store)
                    .with_authority(genesis_authority);
                match submitter.submit_sdk_event(&genesis_op).await {
                    Ok(accepted) => arkret_sdk::EventId::new(accepted.event_id.clone())
                        .map_err(|error| {
                            anyhow::anyhow!("accepted ak.mls.genesis id is invalid: {error}")
                        }),
                    Err(error)
                        if crate::ephemeral::events_submit_rejected_for_reason(
                            &error,
                            &arkret_sdk::ReasonCode::MlsGenesisAlreadyExists,
                        ) =>
                    {
                        submitter
                            .find_mls_genesis_event_id(&realm_for_genesis_lookup)
                            .await?
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "MLS genesis already exists server-side but its accepted Event id is unavailable"
                                )
                            })
                    }
                    Err(error) => Err(error),
                }
            })
            .await;
            match genesis_result {
                Ok(event_id) => {
                    let persist_result = submit_state_store.write(|store| {
                        store.mark_mls_genesis_emitted_with_event(realm_id.clone(), &event_id)
                    });
                    if let Err(error) = persist_result {
                        tracing::warn!(%error, "MLS genesis reference persist failed");
                        return;
                    }
                    accepted_genesis_event_id = Some(event_id);
                }
                Err(err) => {
                    let err_text = err.display().to_string();
                    submit_state_store.write(|store| {
                        store.update_raw_operation_write_state(
                            &operation_id,
                            "failed",
                            None,
                            Some(err_text.clone()),
                        );
                    });
                    tracing::warn!(error = %err_text, "MLS genesis event failed");
                    return;
                }
            }
        }
        let mut accepted_commit_event_id = None::<arkret_sdk::EventId>;
        if let Some(commit_op) = mls_commit_op {
            let commit_state_store = submit_state_store.clone();
            let commit_authority = submit_authority.clone();
            let commit_result = with_authed_api(&base_url, api_token.clone(), |api| async move {
                api.event_submitter()?
                    .with_state_store(commit_state_store)
                    .with_authority(commit_authority)
                    .submit_sdk_event(&commit_op)
                    .await
            })
            .await;
            match commit_result {
                Ok(resp) => {
                    let commit_event_id = match arkret_sdk::EventId::new(resp.event_id.clone()) {
                        Ok(event_id) => event_id,
                        Err(error) => {
                            tracing::warn!(%error, "accepted MLS commit id is invalid");
                            return;
                        }
                    };
                    accepted_commit_event_id = Some(commit_event_id.clone());
                    if let Some(commit_operation_id) = mls_commit_operation_id {
                        submit_state_store.write(|store| {
                            store.record_move_submission_with_event_id(
                                commit_operation_id,
                                Some(resp.event_id),
                                realm_id.clone(),
                                "mls_commit".to_owned(),
                                MoveSubmissionState::from_submit_state("accepted", None),
                                None,
                                None,
                            );
                        });
                    }
                }
                Err(err) => {
                    let err_text = err.display().to_string();
                    submit_state_store.write(|store| {
                        store.update_raw_operation_write_state(
                            &operation_id,
                            "failed",
                            None,
                            Some(err_text.clone()),
                        );
                    });
                    tracing::warn!(error = %err_text, "MLS commit event failed");
                    return;
                }
            }
        }
        let sealed_patch = match patch_plan.seal(
            accepted_commit_event_id.as_ref(),
            accepted_genesis_event_id.as_ref(),
        ) {
            Ok(patch) => patch,
            Err(error) => {
                submit_state_store.write(|store| {
                    store.update_raw_operation_write_state(
                        &operation_id,
                        "failed",
                        None,
                        Some(error.clone()),
                    );
                });
                tracing::warn!(%error, "cannot seal encrypted card update");
                return;
            }
        };
        let submit_event = match crate::operation::ak_ops::strand_update_patch(
            &update_realm_id,
            &update_actor_id,
            &update_strand_id,
            sealed_patch,
        )
        .map(|builder| {
            if calendar_changed {
                builder.causal_refs(calendar_basis_refs)
            } else {
                builder
            }
        })
        .and_then(|builder| builder.build_sdk_event("inkson"))
        {
            Ok(op) => {
                let op = op.with_local_operation_id(local_operation_id);
                match sidecar_effective_scope.as_ref() {
                    Some(effective_scope) => op.with_effective_scope(effective_scope.clone()),
                    None => Ok(op),
                }
            }
            Err(error) => Err(error),
        };
        let submit_event = match submit_event {
            Ok(op) => op,
            Err(error) => {
                let error = format!("cannot update card: {error:#}");
                submit_state_store.write(|store| {
                    store.update_raw_operation_write_state(
                        &operation_id,
                        "failed",
                        None,
                        Some(error.clone()),
                    );
                });
                tracing::warn!(%error, "cannot author encrypted card update");
                return;
            }
        };
        if let Some(reason) = kanban_plaintext_block_reason(guard_security_state, &submit_event) {
            submit_state_store.write(|store| {
                store.update_raw_operation_write_state(
                    &operation_id,
                    "failed",
                    None,
                    Some(reason.clone()),
                );
            });
            tracing::warn!(%reason, "encrypted card update blocked");
            return;
        }
        // The optimistic row was enqueued before the patch could be sealed, so
        // the body lands here, once it exists.
        submit_state_store.write(|store| {
            store.update_raw_operation_body(&operation_id, submit_event.payload_value());
        });
        let update_state_store = submit_state_store.clone();
        let update_authority = submit_authority.clone();
        match with_authed_api(&base_url, api_token.clone(), |api| async move {
            api.event_submitter()?
                .with_state_store(update_state_store)
                .with_authority(update_authority)
                .submit_sdk_event(&submit_event)
                .await
        })
        .await
        {
            Ok(resp) => {
                submit_state_store.write(|store| {
                    store.update_raw_operation_write_state(
                        &operation_id,
                        "accepted",
                        Some(resp.event_id.clone()),
                        None,
                    );
                });
                tracing::debug!(
                    kind = %kind,
                    event_id = %short_protocol_id(&resp.event_id),
                    "detached card update accepted by server"
                );
                if effective_security_encrypted {
                    let Some(backup_account_scope) = backup_account_scope else {
                        tracing::warn!(
                            "active account authority is unavailable after encrypted write"
                        );
                        return;
                    };
                    crate::components::schedule_mls_private_plaintext_backup_after_encrypted_write(
                        base_for_backup_trigger.clone(),
                        api_token.clone(),
                        backup_account_scope.authority.clone(),
                        actor_for_backup_trigger.clone(),
                        backup_account_scope.device_id.to_string(),
                        state_store,
                    );
                    // X11.2 — first-write trigger. After this encrypted write
                    // landed, auto-back up the account secret when possible.
                    // The helper dedupes its server probe per account/session, so
                    // ordinary writes do not list backups repeatedly.
                    if let Some(signal) = backup_trigger_signal {
                        crate::components::maybe_auto_backup_mls_after_encrypted_write(
                            base_for_backup_trigger.clone(),
                            api_token.clone(),
                            backup_account_scope.authority.clone(),
                            actor_for_backup_trigger.clone(),
                            backup_account_scope.device_id.to_string(),
                            state_store,
                            signal,
                        )
                        .await;
                    }
                }
            }
            Err(err) => {
                let error = err.display().to_string();
                submit_state_store.write(|store| {
                    store.update_raw_operation_write_state(
                        &operation_id,
                        "failed",
                        None,
                        Some(error.clone()),
                    );
                });
                // §2.4.1 `epoch_update_required`: arm the coverage repair so the
                // per-Realm MLS effect advances the epoch. Without this the
                // refusal is just another failed write and the scope never
                // recovers.
                let paused = submit_state_store.write(|store| {
                    crate::mls::coverage_liveness::note_e2ee_submit_refusal_in_store(
                        store,
                        &realm_id,
                        None,
                        err.inner(),
                    )
                });
                if paused {
                    tracing::warn!(
                        kind = %kind,
                        "card update paused while MLS epoch advances to cover governance Seal"
                    );
                } else {
                    tracing::warn!(kind = %kind, %error, "detached card update failed");
                }
            }
        }
    });
    true
}
