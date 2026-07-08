use dioxus::prelude::*;
use serde_json::{Value, json};

use super::model::*;
use super::{
    apply_card_detail_draft, card_detail_activity_summary, card_detail_update_patch,
    collect_encryptable_private_patch_values, kanban_plaintext_block_reason,
    replace_private_patch_values,
};
use crate::local_state::{LocalStateStore, MoveSubmissionState};
// YGN-ARCH-01 step 2: the MLS commit/genesis event construction moved to
// `crate::mls::group_events` (it serves any effective scope and is consumed
// by `mls::admission` / `circle_mls` / `sync_engine`, not just kanban).
use crate::mls::group_events::{
    build_creator_mls_genesis_event, ensure_creator_mls_snapshot_for_encrypted_scope,
    mls_commit_event_from_store,
};
use crate::operation::sdk_event_local_operation_id;
use crate::views::helpers::{short_protocol_id, with_authed_api};

/// The MLS events an encrypted write must submit, in submit order: the
/// one-time `ck.mls.genesis` (if not yet emitted) MUST precede any forced
/// `ck.mls.commit` so the server has the group at epoch 0 before the commit
/// bumps it.
#[derive(Default, Debug)]
pub(super) struct EncryptedWriteMlsEvents {
    pub genesis: Option<cokret_sdk::Event>,
    pub commit: Option<cokret_sdk::Event>,
    /// X14 — the post-commit MLS snapshot. Persisted by the caller ONLY
    /// after the server ACCEPTS `commit`, so the local snapshot epoch never
    /// races ahead of the server's accepted epoch (the root cause of
    /// permanent `mls_epoch_skew`). `None` when the encrypted write rides the
    /// current epoch without forcing a commit.
    pub snapshot: Option<crate::mls::persistence::MlsSnapshotEnvelope>,
}

pub(super) fn encrypt_private_card_detail_patch_values(
    patch: Value,
    realm_id: &str,
    strand_id: &str,
    actor_id: &str,
    device_id: &str,
    mut state_store: Signal<LocalStateStore>,
) -> Result<(Value, EncryptedWriteMlsEvents), String> {
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let mut store = state_store.write();
    encrypt_private_card_detail_patch_values_with_store(
        patch,
        realm_id,
        strand_id,
        actor_id,
        device_id,
        &mut store,
        secure_store.as_ref(),
    )
}

pub(super) fn encrypt_private_card_detail_patch_values_with_store(
    patch: Value,
    realm_id: &str,
    strand_id: &str,
    actor_id: &str,
    device_id: &str,
    state_store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Result<(Value, EncryptedWriteMlsEvents), String> {
    let values = collect_encryptable_private_patch_values(&patch)?;
    if values.is_empty() {
        return Ok((patch, EncryptedWriteMlsEvents::default()));
    }
    let plaintext_values = values
        .iter()
        .map(|(_, bytes)| bytes.clone())
        .collect::<Vec<_>>();
    apply_local_mls_welcomes_for_realm(state_store, secure_store, realm_id, actor_id, device_id)?;
    let fresh_summary = ensure_creator_mls_snapshot_for_encrypted_scope(
        state_store,
        secure_store,
        realm_id,
        actor_id,
        device_id,
    )?;
    // Build genesis BEFORE the first commit mutates the group past epoch 0.
    let genesis_event = build_creator_mls_genesis_event(
        state_store,
        realm_id,
        actor_id,
        device_id,
        fresh_summary.as_ref(),
    )?;
    let (schedule_hash, _member_dids, encrypted_values, commit_envelope, new_snapshot) =
        crate::mls::runtime::encrypt_values_with_device_snapshot(
            state_store,
            secure_store,
            realm_id,
            actor_id,
            device_id,
            KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
            &plaintext_values,
        )
        .map_err(|err| err.user_message())?;
    let commit_event = match commit_envelope.as_ref() {
        Some(commit_envelope) => Some(mls_commit_event_from_store(
            state_store,
            realm_id,
            actor_id,
            &schedule_hash,
            commit_envelope,
        )?),
        None => None,
    };
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
    synthesis_entry_id: Option<String>,
    synthesis_revision_body: Option<String>,
    mut selected_card: Signal<Option<KanbanCard>>,
    mut state_store: Signal<LocalStateStore>,
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
    let (patch, mls_events) = if effective_security_encrypted {
        match encrypt_private_card_detail_patch_values(
            patch,
            &realm_id,
            &current.id,
            &actor_id,
            &device_id,
            state_store,
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
    } = mls_events;

    let op = match crate::operation::ck_ops::strand_update_patch(
        &realm_id,
        &actor_id,
        &current.id,
        patch,
    ) {
        Ok(builder) => builder.build_sdk_event("yougen"),
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
    // The board itself re-renders from the appended `ck.strand.update` op
    // below — `columns` is a `use_memo` over `raw_operations`, folded by
    // `overlay_local_card_update_records`, so there is no direct signal write.
    let mut updated_card = current.clone();
    apply_card_detail_draft(&mut updated_card, &draft);
    selected_card.set(Some(updated_card));

    let operation_id = sdk_event_local_operation_id(&op).to_owned();
    let synthesis_entry_id = synthesis_revision_body
        .as_ref()
        .map(|_| synthesis_entry_id.unwrap_or_else(|| operation_id.clone()));
    let local_synthesis_revision_body = synthesis_revision_body
        .clone()
        .filter(|_| !effective_security_encrypted);
    state_store.write().append_raw_operation(
        operation_id.clone(),
        Some(realm_id.clone()),
        json!({
            "kind": op.kind.as_str(),
            "operation_id": operation_id.clone(),
            "actor_id": op.actor_id.to_string(),
            "created_at": op.created_at.to_rfc3339(),
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
    let submit_event = op;
    spawn(async move {
        // Genesis MUST land before the first commit so the server has the
        // group at epoch 0 before the commit bumps it to 1. A duplicate
        // genesis (`mls_genesis_already_exists`) is treated as success.
        if let Some(genesis_op) = mls_genesis_op {
            let genesis_event_id = genesis_op.event_id.clone();
            let genesis_result = with_authed_api(&base_url, api_token.clone(), |api| async move {
                api.event_submitter()?.submit_sdk_event(&genesis_op).await
            })
            .await;
            match genesis_result {
                Ok(_) => {
                    state_store
                        .write()
                        .mark_mls_genesis_emitted_with_event(realm_id.clone(), &genesis_event_id);
                }
                Err(err) => {
                    let err_text = err.display().to_string();
                    if err_text.contains("mls_genesis_already_exists") {
                        // Already installed server-side — record locally and proceed.
                        state_store
                            .write()
                            .mark_mls_genesis_emitted(realm_id.clone());
                    } else {
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
        }
        if let Some(commit_op) = mls_commit_op {
            let commit_result = with_authed_api(&base_url, api_token.clone(), |api| async move {
                api.event_submitter()?.submit_sdk_event(&commit_op).await
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
                    if let Some(snapshot) = mls_new_snapshot {
                        state_store
                            .write()
                            .save_mls_snapshot(realm_id.clone(), snapshot);
                        // §7.10 continuous backup: the accepted commit advanced
                        // the epoch, so re-upload this Realm's mls_history
                        // series tail (debounced; no-op until the 24-word
                        // Recovery Key exists).
                        crate::components::schedule_mls_history_backup_after_commit(
                            base_for_backup_trigger.clone(),
                            api_token.clone(),
                            actor_for_backup_trigger.clone(),
                            device_for_sidecar_backup.clone(),
                            realm_id.clone(),
                            state_store,
                        );
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
                board_status.set(format!("{kind} operation failed: {}", err.display()));
            }
        }
    });
    true
}
