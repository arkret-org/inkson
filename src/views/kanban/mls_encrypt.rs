use serde_json::{Value, json};

use super::model::*;
use super::{
    apply_card_detail_draft, card_detail_activity_summary, card_detail_update_patch,
    collect_encryptable_private_patch_values, kanban_plaintext_block_reason,
    replace_private_patch_values,
};
// YGN-ARCH-01 step 2: the MLS commit/genesis event construction moved to
// `crate::mls::group_events` (it serves any effective scope and is consumed
// by `mls::admission` / `circle_mls` / `sync_engine`, not just kanban).
use crate::mls::group_events::{
    build_creator_mls_genesis_event, ensure_creator_mls_snapshot_for_encrypted_scope,
    mls_commit_event_from_store,
};
use crate::operation::sdk_event_local_operation_id;
use crate::state::{LocalStateStore, MoveSubmissionState};
use crate::transport::auth::with_authed_api;
use crate::views::helpers::short_protocol_id;

pub(super) fn rebind_encrypted_group_state_ref(
    value: &mut Value,
    provisional_ref: &arkret_sdk::EventId,
    accepted_ref: &arkret_sdk::EventId,
) -> Result<usize, String> {
    let mut rebound = 0;
    match value {
        Value::Array(values) => {
            for value in values {
                rebound += rebind_encrypted_group_state_ref(value, provisional_ref, accepted_ref)?;
            }
        }
        Value::Object(object) => {
            let is_envelope = object.get("version").and_then(Value::as_str) == Some("1.0")
                && object.get("scheme").and_then(Value::as_str).is_some()
                && object
                    .get("key_ref")
                    .and_then(|key_ref| key_ref.get("group_state_ref"))
                    .and_then(Value::as_str)
                    == Some(provisional_ref.as_str());
            if is_envelope {
                let key_ref = object
                    .get_mut("key_ref")
                    .and_then(Value::as_object_mut)
                    .ok_or_else(|| "encrypted envelope key_ref is invalid".to_owned())?;
                key_ref.insert(
                    "group_state_ref".to_owned(),
                    Value::String(accepted_ref.to_string()),
                );
                serde_json::from_value::<arkret_sdk::EncryptedEnvelope>(value.clone())
                    .map_err(|error| format!("rebound encrypted envelope is invalid: {error}"))?
                    .validate()
                    .map_err(|error| format!("rebound encrypted envelope is invalid: {error}"))?;
                return Ok(1);
            }
            for value in object.values_mut() {
                rebound += rebind_encrypted_group_state_ref(value, provisional_ref, accepted_ref)?;
            }
        }
        _ => {}
    }
    Ok(rebound)
}

/// The MLS events an encrypted write must submit, in submit order: the
/// one-time `ak.mls.genesis` (if not yet emitted) MUST precede any forced
/// `ak.mls.commit` so the server has the group at epoch 0 before the commit
/// bumps it.
#[derive(Default, Debug)]
pub(super) struct EncryptedWriteMlsEvents {
    pub genesis: Option<arkret_sdk::Event>,
    pub commit: Option<arkret_sdk::Event>,
    /// X14 — the post-commit MLS snapshot. Persisted by the caller ONLY
    /// after the server ACCEPTS `commit`, so the local snapshot epoch never
    /// races ahead of the server's accepted epoch (the root cause of
    /// permanent `mls_epoch_skew`). `None` when the encrypted write rides the
    /// current epoch without forcing a commit.
    pub snapshot: Option<crate::mls::persistence::MlsSnapshotEnvelope>,
    /// Must commit before genesis/commit/content submission begins.
    pub pending_history_secrets: Option<crate::state::PendingHistorySecrets>,
}

#[derive(Clone, Debug)]
pub(super) struct SidecarTrackWriteContext {
    pub circle_id: String,
    pub binding: Option<arkret_sdk::SidecarMlsBinding>,
    pub ready: bool,
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
) -> Result<(Value, EncryptedWriteMlsEvents), String> {
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
) -> Result<(Value, EncryptedWriteMlsEvents), String> {
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
) -> Result<(Value, EncryptedWriteMlsEvents), String> {
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
        return Ok((patch, EncryptedWriteMlsEvents::default()));
    }
    let plaintext_values = values
        .iter()
        .map(|(_, bytes)| bytes.clone())
        .collect::<Vec<_>>();
    let circle_id = sidecar.map(|context| context.circle_id.as_str());
    let fresh_summary = if circle_id.is_none() {
        apply_local_mls_welcomes_for_realm(
            state_store,
            secure_store,
            realm_id,
            actor_id,
            device_id,
        )?;
        ensure_creator_mls_snapshot_for_encrypted_scope(
            state_store,
            secure_store,
            realm_id,
            actor_id,
            device_id,
        )?
    } else {
        if state_store
            .mls_snapshot_for_effective_scope(realm_id, circle_id)
            .is_none()
        {
            return Err("Private Sidecar MLS snapshot is unavailable".to_owned());
        }
        None
    };
    // Build genesis BEFORE the first commit mutates the group past epoch 0.
    let genesis_event = if let Some(sidecar) = sidecar {
        crate::mls::group_events::build_creator_mls_genesis_event_for_effective_scope_with_binding(
            state_store,
            realm_id,
            Some(&sidecar.circle_id),
            actor_id,
            device_id,
            fresh_summary.as_ref(),
            sidecar.binding.clone(),
        )?
    } else {
        build_creator_mls_genesis_event(
            state_store,
            realm_id,
            actor_id,
            device_id,
            fresh_summary.as_ref(),
        )?
    };
    let aad_realm_id = arkret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|error| format!("invalid Realm id for encrypted AAD: {error:?}"))?;
    let envelope_aad = arkret_sdk::EncryptedEnvelopeAad::hidden(aad_realm_id, "ak.strand.update");
    let (
        schedule_hash,
        _member_dids,
        mut encrypted_values,
        prepared_commit,
        new_snapshot,
        pending_history_secrets,
    ) = crate::mls::runtime::encrypt_values_with_device_snapshot_for_effective_scope(
        state_store,
        secure_store,
        realm_id,
        actor_id,
        device_id,
        KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
        &plaintext_values,
        envelope_aad,
        circle_id,
        sidecar.and_then(|context| context.binding.as_ref()),
    )
    .map_err(|err| err.user_message())?;
    let commit_event = match prepared_commit.as_ref() {
        Some(prepared_commit) => Some(if let Some(sidecar) = sidecar {
            crate::mls::group_events::mls_commit_event_from_store_for_effective_scope_with_sidecar_binding(
                state_store,
                realm_id,
                &sidecar.circle_id,
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
    let group_state_ref = if let Some(commit_event) = commit_event.as_ref() {
        commit_event.event_id.to_string()
    } else if first_payload.epoch == 0
        && let Some(genesis_event) = genesis_event.as_ref()
    {
        genesis_event.event_id.to_string()
    } else {
        crate::mls::group_events::mls_base_epoch_ref_for_scope(
            state_store,
            realm_id,
            circle_id,
            first_payload.group_id.as_str(),
            first_payload.epoch,
        )?
    };
    for encrypted_value in &mut encrypted_values {
        let payload =
            serde_json::from_value::<arkret_sdk::EncryptedPayload>(encrypted_value.clone())
                .map_err(|error| format!("invalid encrypted patch payload: {error}"))?;
        if payload.group_id != first_payload.group_id || payload.epoch != first_payload.epoch {
            return Err("encrypted patch values do not share one MLS group and epoch".to_owned());
        }
        let aad = payload
            .aad
            .clone()
            .ok_or_else(|| "encrypted patch payload is missing canonical AAD".to_owned())?;
        let envelope = arkret_sdk::mls::encrypted_envelope_from_payload(
            &payload,
            aad,
            arkret_sdk::EncryptedEnvelopeAadVisibility::Hidden,
            // `hidden` is at or below every possible Realm ceiling, so the
            // fail-closed `from_declared(None)` resolution always admits it. A
            // caller that starts emitting `routing_digest` MUST pass the Realm's
            // accepted `aad_visibility` component here instead.
            arkret_sdk::AadVisibilityCeiling::from_declared(None),
            &group_state_ref,
        )
        .map_err(|error| format!("build encrypted Strand patch envelope: {error}"))?;
        *encrypted_value = serde_json::to_value(envelope)
            .map_err(|error| format!("serialize encrypted Strand patch envelope: {error}"))?;
    }
    // X5.1 — encryption succeeded. Persist the author's own plaintext into
    // the local-only sidecar so a later re-projection (refresh / board
    // switch / live poll) can render the author's own content, which can
    // never be recovered by decrypting the author's own MLS ciphertext.
    // The stored value is the JSON-serialized patch *value* (the same
    // `plaintext_values` bytes that were just encrypted) as a UTF-8 string;
    // the read path parses it back with `serde_json::from_str` and feeds it
    // to `strand_body_display_text`, keeping write+read symmetric. This is
    // local-only and NEVER enters the op / `append_raw_operation` payload.
    for (path, plaintext_bytes) in &values {
        if let Ok(plaintext_str) = std::str::from_utf8(plaintext_bytes) {
            state_store.save_private_plaintext(realm_id, strand_id, path, plaintext_str);
        }
    }
    let paths = values.into_iter().map(|(path, _)| path).collect::<Vec<_>>();
    let mut encrypted_patch = patch;
    replace_private_patch_values(&mut encrypted_patch, &paths, encrypted_values)?;
    Ok((
        encrypted_patch,
        EncryptedWriteMlsEvents {
            genesis: genesis_event,
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

fn apply_local_mls_welcomes_for_realm(
    state_store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> Result<(), String> {
    if state_store.mls_snapshot_for(realm_id).is_some() {
        return Ok(());
    }
    let inbox = state_store.to_device_inbox();
    let messages = crate::mls::runtime::collect_mls_welcome_messages_for_realm(&inbox, realm_id);
    if messages.is_empty() {
        return Ok(());
    }
    let messages_value = json!({ "messages": messages });
    let outcome = crate::mls::runtime::apply_welcome_messages_with_device_snapshot(
        state_store,
        secure_store,
        realm_id,
        actor_id,
        device_id,
        &messages_value,
    )
    .map_err(|err| err.user_message())?;
    if state_store.mls_snapshot_for(realm_id).is_none() && outcome.failed > 0 {
        return Err(format!(
            "MLS Welcome could not be applied from local device inbox: {}",
            outcome
                .first_error
                .as_deref()
                .unwrap_or("unknown MLS Welcome error")
        ));
    }
    Ok(())
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
    let (patch, mls_events) = if effective_security_encrypted {
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
        (patch, EncryptedWriteMlsEvents::default())
    };
    let EncryptedWriteMlsEvents {
        genesis: mls_genesis_op,
        commit: mls_commit_op,
        snapshot: mls_new_snapshot,
        pending_history_secrets,
    } = mls_events;

    let op = match crate::operation::ak_ops::strand_update_patch(
        &realm_id,
        &actor_id,
        &current.id,
        patch,
    ) {
        Ok(builder) => {
            let builder = if calendar_changed {
                builder.causal_refs(current.calendar_schedule_basis_refs())
            } else {
                builder
            };
            builder.build_sdk_event("inkson")
        }
        Err(err) => {
            board_status.set(format!("cannot update card: {err:#}"));
            return false;
        }
    };
    let op = match op {
        Ok(event) => event,
        Err(err) => {
            board_status.set(format!("cannot update card: {err}"));
            return false;
        }
    };
    // R4: feed the guard the three-state security signal. An explicit
    // per-card `security_encrypted` flag (`Some`) wins; otherwise fall back to
    // the scope three-state so an unknown projection fails closed.
    let guard_security_state = current
        .security_encrypted
        .map(Some)
        .unwrap_or(scope_security_encrypted);
    if let Some(reason) = kanban_plaintext_block_reason(guard_security_state, &op) {
        board_status.set(reason);
        return false;
    }

    // Optimistic detail-panel feedback: apply the draft to the open card.
    // The board itself re-renders from the appended `ak.strand.update` op
    // below — `columns` is a `use_memo` over `raw_operations`, folded by
    // `overlay_local_card_update_records`, so there is no direct signal write.
    let mut updated_card = current.clone();
    apply_card_detail_draft(&mut updated_card, &draft);
    if sidecar_track_write.is_none() {
        selected_card.set(Some(updated_card));
    }

    let operation_id = sdk_event_local_operation_id(&op).to_owned();
    let synthesis_entry_id = synthesis_revision_body
        .as_ref()
        .map(|_| synthesis_entry_id.unwrap_or_else(|| operation_id.clone()));
    let local_synthesis_revision_body = synthesis_revision_body
        .clone()
        .filter(|_| !effective_security_encrypted);
    state_store.write().enqueue_local_projection_command(
        operation_id.clone(),
        Some(realm_id.clone()),
        json!({
            "kind": op.kind.as_str(),
            "operation_id": operation_id.clone(),
            "actor_id": op.actor_id.to_string(),
            "created_at": arkret_sdk::canonical::format_timestamp_canonical(op.created_at),
            "write_state": "queued",
            "body": op.payload.clone(),
            "activity_summary": card_detail_activity_summary(&current, &draft),
            "synthesis_entry_id": synthesis_entry_id,
            "synthesis_revision_body": local_synthesis_revision_body,
            "encrypted_payload_local": effective_security_encrypted,
        }),
    );
    board_status.set(format!(
        "submitting {} operation {}",
        op.kind.as_str(),
        short_protocol_id(&operation_id)
    ));
    let api_token = token();
    let strand_id = current.id.clone();
    let kind = op.kind.as_str().to_owned();
    let mls_commit_operation_id = mls_commit_op
        .as_ref()
        .map(|op| sdk_event_local_operation_id(op).to_owned());
    // X11.2 — first-write trigger. Read the context-provided
    // `needs_mls_backup` signal HERE (inside the Dioxus scope), so the
    // encrypted-write success arm can flip the backup prompt on directly,
    // bypassing the fragile boot detection effect. Best-effort: `None` when
    // no provider is mounted (unit tests / non-app callers).
    let backup_trigger_signal = crate::components::try_needs_mls_backup_signal();
    let base_for_backup_trigger = base_url.clone();
    let actor_for_backup_trigger = actor_id.clone();
    let device_for_sidecar_backup = device_id.clone();
    let circle_id = sidecar_track_write.map(|context| context.circle_id);
    let mut submit_event = op;
    spawn(async move {
        if let Some(pending) = pending_history_secrets {
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            if let Err(error) = pending.persist(secure_store.as_ref()).await {
                state_store.write().update_raw_operation_write_state(
                    &operation_id,
                    "failed",
                    None,
                    Some(error.to_string()),
                );
                board_status.set(format!("MLS history-secret persist failed: {error}"));
                return;
            }
            state_store.write().publish_history_secrets(pending);
        }
        // Genesis MUST land before the first commit so the server has the
        // group at epoch 0 before the commit bumps it to 1. A duplicate
        // genesis is success only after resolving the exact already-accepted
        // Event id; merely setting the emitted flag strands secure messages
        // without their mandatory group_state_ref.
        if let Some(genesis_op) = mls_genesis_op {
            let genesis_event_id = genesis_op.event_id.clone();
            let provisional_genesis_event_id = genesis_event_id.clone();
            let realm_for_genesis_lookup = realm_id.clone();
            let genesis_result = with_authed_api(&base_url, api_token.clone(), |api| async move {
                let submitter = api.event_submitter()?;
                match submitter.submit_sdk_event(&genesis_op).await {
                    Ok(_) => Ok(genesis_event_id),
                    Err(error)
                        if error
                            .to_string()
                            .contains("mls_genesis_already_exists") =>
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
                Ok(accepted_genesis_event_id) => {
                    state_store.write().mark_mls_genesis_emitted_with_event(
                        realm_id.clone(),
                        &accepted_genesis_event_id,
                    );
                    if accepted_genesis_event_id != provisional_genesis_event_id {
                        let rebound =
                            submit_event
                                .payload
                                .values_mut()
                                .try_fold(0, |count, value| {
                                    rebind_encrypted_group_state_ref(
                                        value,
                                        &provisional_genesis_event_id,
                                        &accepted_genesis_event_id,
                                    )
                                    .map(|rebound| count + rebound)
                                });
                        match rebound {
                            Ok(rebound) if rebound > 0 => {}
                            Ok(_) => {
                                board_status.set(
                                    "MLS genesis reference recovery found no encrypted Strand envelope"
                                        .to_owned(),
                                );
                                return;
                            }
                            Err(error) => {
                                board_status
                                    .set(format!("MLS genesis reference recovery failed: {error}"));
                                return;
                            }
                        }
                    }
                }
                Err(err) => {
                    let err_text = err.display().to_string();
                    state_store.write().update_raw_operation_write_state(
                        &operation_id,
                        "failed",
                        None,
                        Some(err_text.clone()),
                    );
                    let selected = selected_card.read().clone();
                    if let Some(mut card) = selected
                        && card.id == strand_id
                    {
                        card.state = CardState::SoftFailed;
                        selected_card.set(Some(card));
                    }
                    board_status.set(format!("MLS genesis event failed: {err_text}"));
                    return;
                }
            }
        }
        if let Some(commit_op) = mls_commit_op {
            let commit_event_id = commit_op.event_id.clone();
            let snapshot_for_submit = mls_new_snapshot.clone();
            let realm_for_submit = realm_id.clone();
            let circle_for_submit = circle_id.clone();
            let post_accept_store = crate::app::runtime_adapter::state_store_handle(state_store);
            let commit_result = with_authed_api(&base_url, api_token.clone(), |api| async move {
                match (snapshot_for_submit, circle_for_submit.as_deref()) {
                    (Some(snapshot), None) => {
                        api.event_submitter()?
                            .submit_mls_event_with_snapshot(
                                &commit_op,
                                realm_for_submit,
                                snapshot,
                                post_accept_store,
                            )
                            .await
                    }
                    (Some(_), Some(_)) | (None, _) => {
                        api.event_submitter()?.submit_sdk_event(&commit_op).await
                    }
                }
            })
            .await;
            match commit_result {
                Ok(resp) => {
                    // X14 — persist-on-accept: the server accepted this commit,
                    // so NOW advance the local snapshot to the post-commit
                    // epoch. This keeps `snapshot.epoch == server.epoch` in
                    // lockstep; if the commit had been rejected we'd skip this
                    // and the snapshot would stay at the pre-commit epoch, so
                    // the next write retries at the correct `expected_prev_epoch`
                    // instead of skewing forever.
                    if mls_new_snapshot.is_some() {
                        if let (Some(circle_id), Some(snapshot)) =
                            (circle_id.as_deref(), mls_new_snapshot.clone())
                        {
                            if let Err(error) = state_store
                                .write()
                                .record_mls_group_state_ref_for_effective_scope(
                                    realm_id.clone(),
                                    Some(circle_id),
                                    snapshot.group_id.as_str(),
                                    snapshot.epoch,
                                    commit_event_id,
                                )
                            {
                                board_status
                                    .set(format!("MLS commit reference persist failed: {error}"));
                                return;
                            }
                            state_store.write().save_mls_snapshot_for_effective_scope(
                                realm_id.clone(),
                                Some(circle_id),
                                snapshot,
                            );
                        }
                        // §7.10 continuous backup: the accepted commit advanced
                        // the epoch, so re-upload this Realm's mls_history
                        // series tail (debounced; no-op until the 24-word
                        // Recovery Key exists).
                        if circle_id.is_none() {
                            crate::components::schedule_mls_history_backup_after_commit(
                                base_for_backup_trigger.clone(),
                                api_token.clone(),
                                actor_for_backup_trigger.clone(),
                                device_for_sidecar_backup.clone(),
                                realm_id.clone(),
                                state_store,
                            );
                        }
                    }
                    if let Some(commit_operation_id) = mls_commit_operation_id {
                        state_store.write().record_move_submission_with_event_id(
                            commit_operation_id,
                            Some(resp.event_id),
                            realm_id.clone(),
                            "mls_commit".to_owned(),
                            MoveSubmissionState::from_submit_state("accepted", None),
                            None,
                            None,
                        );
                    }
                }
                Err(err) => {
                    let err_text = err.display().to_string();
                    state_store.write().update_raw_operation_write_state(
                        &operation_id,
                        "failed",
                        None,
                        Some(err_text.clone()),
                    );
                    let selected = selected_card.read().clone();
                    if let Some(mut card) = selected
                        && card.id == strand_id
                    {
                        card.state = CardState::SoftFailed;
                        selected_card.set(Some(card));
                    }
                    board_status.set(format!("MLS commit event failed: {err_text}"));
                    return;
                }
            }
        }
        match with_authed_api(&base_url, api_token.clone(), |api| async move {
            api.event_submitter()?.submit_sdk_event(&submit_event).await
        })
        .await
        {
            Ok(resp) => {
                state_store.write().update_raw_operation_write_state(
                    &operation_id,
                    "accepted",
                    Some(resp.event_id.clone()),
                    None,
                );
                let selected = selected_card.read().clone();
                if let Some(mut card) = selected
                    && card.id == strand_id
                {
                    card.state = CardState::Accepted;
                    selected_card.set(Some(card));
                }
                board_status.set(format!(
                    "{kind} operation accepted by server (event_id={})",
                    short_protocol_id(&resp.event_id)
                ));
                if effective_security_encrypted {
                    crate::components::schedule_mls_private_plaintext_backup_after_encrypted_write(
                        base_for_backup_trigger.clone(),
                        api_token.clone(),
                        actor_for_backup_trigger.clone(),
                        device_for_sidecar_backup.clone(),
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
                            actor_for_backup_trigger.clone(),
                            device_for_sidecar_backup.clone(),
                            state_store,
                            signal,
                        )
                        .await;
                    }
                }
            }
            Err(err) => {
                state_store.write().update_raw_operation_write_state(
                    &operation_id,
                    "failed",
                    None,
                    Some(err.display().to_string()),
                );
                let selected = selected_card.read().clone();
                if let Some(mut card) = selected
                    && card.id == strand_id
                {
                    card.state = CardState::SoftFailed;
                    selected_card.set(Some(card));
                }
                // §2.4.1 `epoch_update_required`: arm the coverage repair so the
                // per-Realm MLS effect advances the epoch. Without this the
                // refusal is just another failed write and the scope never
                // recovers.
                let paused = crate::mls::coverage_liveness::note_e2ee_submit_refusal(
                    &mut state_store,
                    &realm_id,
                    None,
                    err.inner(),
                );
                board_status.set(if paused {
                    format!(
                        "{kind} operation paused: MLS epoch must cover the latest governance Seal; \
                         advancing the epoch"
                    )
                } else {
                    format!("{kind} operation failed: {}", err.display())
                });
            }
        }
    });
    true
}
