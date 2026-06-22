use dioxus::prelude::*;
use serde_json::{Value, json};

use super::model::*;
use super::{
    apply_card_detail_draft, card_detail_activity_summary, card_detail_update_patch,
    collect_encryptable_private_patch_values, kanban_plaintext_block_reason,
    replace_private_patch_values, set_card_state_in_columns,
};
use crate::local_state::{LocalSealView, LocalStateStore, MoveSubmissionState};
use crate::operation::{trim_realm_id, uuid_v7};
use crate::views::helpers::{short_protocol_id, with_authed_api};

fn sdk_event_local_operation_id(event: &cokret_sdk::Event) -> &str {
    event
        .unsigned
        .get("local_operation_idempotency_alias")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| event.event_id.as_str())
}

pub(super) fn kanban_sha256_hash_from_ref(value: &str) -> Option<String> {
    if let Some(hex) = value.strip_prefix("sha256:")
        && hex.len() == 64
        && hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Some(value.to_owned());
    }
    for prefix in ["ck:seal:", "ck:state:"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            return kanban_sha256_hash_from_ref(rest);
        }
    }
    None
}

pub(super) fn kanban_object_ref_from_seal_ref(value: &str) -> Option<String> {
    if value.starts_with("ck:event:") && cokret_sdk::EventId::new(value.to_owned()).is_ok() {
        return Some(value.to_owned());
    }
    if value.starts_with("ck:blob:sha256:")
        && value
            .strip_prefix("ck:blob:")
            .and_then(kanban_sha256_hash_from_ref)
            .is_some()
    {
        return Some(value.to_owned());
    }
    if let Some(hash) = kanban_sha256_hash_from_ref(value) {
        return Some(hash);
    }
    None
}

pub(super) fn kanban_mls_base_epoch_ref_for_scope(
    seal_view: &LocalSealView,
    realm_id: &str,
    circle_id: Option<&str>,
) -> String {
    seal_view
        .frontier
        .iter()
        .chain(seal_view.leaves.iter())
        .chain(seal_view.state_root.iter())
        .find_map(|value| kanban_object_ref_from_seal_ref(value))
        .unwrap_or_else(|| {
            crate::canonical::canonical_sha256(&json!({
                "kind": "kanban_mls_base_epoch",
                "realm_id": realm_id,
                "circle_id": circle_id,
                "epoch": seal_view.mls_epoch.unwrap_or(0),
            }))
            .unwrap_or_else(|_| {
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned()
            })
        })
}

pub(super) fn kanban_mls_membership_frontier(
    seal_view: &LocalSealView,
    fallback_event_id: &cokret_sdk::EventId,
) -> Vec<cokret_sdk::EventId> {
    let mut frontier = seal_view
        .frontier
        .iter()
        .chain(seal_view.leaves.iter())
        .filter_map(|value| cokret_sdk::EventId::new(value.clone()).ok())
        .collect::<Vec<_>>();
    if frontier.is_empty() {
        frontier.push(fallback_event_id.clone());
    }
    frontier.sort();
    frontier.dedup();
    frontier
}

pub(super) fn kanban_mls_policy_root(
    seal_view: &LocalSealView,
    realm_id: &str,
) -> Result<cokret_sdk::Hash, String> {
    let hash = seal_view
        .state_root
        .as_deref()
        .and_then(kanban_sha256_hash_from_ref)
        .unwrap_or_else(|| {
            crate::canonical::canonical_sha256(&json!({
                "kind": "kanban_mls_policy_root",
                "realm_id": realm_id,
                "frontier": seal_view.frontier,
                "state_root": seal_view.state_root,
            }))
            .unwrap_or_else(|_| {
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned()
            })
        });
    cokret_sdk::Hash::new(hash).map_err(|err| format!("invalid MLS policy root hash: {err:?}"))
}

pub(super) fn projection_creator_matches_actor(projection: &Value, actor_id: &str) -> bool {
    let actor = actor_id.trim();
    if actor.is_empty() {
        return false;
    }
    for source in [
        projection,
        projection.get("summary").unwrap_or(&Value::Null),
        projection.get("object").unwrap_or(&Value::Null),
        projection.get("realm").unwrap_or(&Value::Null),
        projection.get("metadata").unwrap_or(&Value::Null),
    ] {
        for key in [
            "owner",
            "created_by",
            "created_by_principal",
            "creator",
            "creator_did",
        ] {
            if json_path_string(Some(source), &[key]).as_deref() == Some(actor) {
                return true;
            }
        }
    }
    false
}

fn circle_effective_scope(
    realm_id: &str,
    circle_id: &str,
) -> Result<cokret_sdk::models::EffectiveScope, String> {
    Ok(cokret_sdk::models::EffectiveScope::Circle {
        realm_id: cokret_sdk::RealmId::new(trim_realm_id(realm_id))
            .map_err(|err| format!("invalid Circle scope Realm id: {err:?}"))?,
        circle_id: cokret_sdk::CircleId::new(circle_id.to_owned())
            .map_err(|err| format!("invalid Circle scope Circle id: {err:?}"))?,
    })
}

pub(super) fn ensure_creator_mls_snapshot_for_encrypted_scope(
    state_store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> Result<Option<crate::mls::runtime::InitialMlsSnapshotSummary>, String> {
    if state_store.mls_snapshot_for(realm_id).is_some() {
        return Ok(None);
    }
    let state = state_store.load();
    let Some(projection) = crate::security_state::security_projection_for_scope_id(
        &state.realm_tree_projections,
        realm_id,
    ) else {
        return Ok(None);
    };
    if !crate::security_state::realm_projection_is_encrypted(projection)
        || !projection_creator_matches_actor(projection, actor_id)
    {
        return Ok(None);
    }
    crate::mls::runtime::ensure_creator_mls_snapshot(
        state_store,
        secure_store,
        realm_id,
        actor_id,
        device_id,
    )
    .map_err(|err| err.user_message())
}

/// Build the `ck.mls.genesis` SDK event for a creator group that has a
/// local snapshot but whose genesis has not yet been submitted to soland.
///
/// Returns `None` when genesis was already emitted for this Realm (idempotent —
/// see [`LocalStateStore::mls_genesis_emitted_for`]) or when there is no local
/// snapshot. `fresh_summary` carries the just-created group's epoch-0 ratchet
/// tree / schedule hash captured by `ensure_creator_mls_snapshot`; genesis MUST
/// describe the group at epoch 0, so this builder only emits when that fresh
/// epoch-0 material is available (the normal create-then-first-write path).
///
/// The genesis governance binding installs epoch `0 -> 0` and mirrors the
/// commit path's realm_id / membership_frontier / policy_root derivation.
pub(crate) fn build_creator_mls_genesis_event(
    state_store: &LocalStateStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    fresh_summary: Option<&crate::mls::runtime::InitialMlsSnapshotSummary>,
) -> Result<Option<cokret_sdk::Event>, String> {
    build_creator_mls_genesis_event_for_effective_scope(
        state_store,
        realm_id,
        None,
        actor_id,
        device_id,
        fresh_summary,
    )
}

pub(crate) fn build_creator_mls_genesis_event_for_effective_scope(
    state_store: &LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    device_id: &str,
    fresh_summary: Option<&crate::mls::runtime::InitialMlsSnapshotSummary>,
) -> Result<Option<cokret_sdk::Event>, String> {
    let circle = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
    if state_store.mls_genesis_emitted_for_effective_scope(realm_id, circle) {
        return Ok(None);
    }
    // Genesis describes the group at epoch 0. We can only build a
    // contract-correct genesis from the just-created epoch-0 material; once the
    // group has committed past epoch 0 the epoch-0 ratchet tree is gone. The
    // server lazily defaults a never-seen group to epoch 0 anyway, so missing
    // this window is non-fatal (commits still work).
    let Some(summary) = fresh_summary else {
        return Ok(None);
    };
    if summary.realm_id != realm_id {
        return Ok(None);
    }
    let seal_view = state_store.seal_view_for_realm(realm_id);
    let event_id = format!("ck:event:{}", uuid_v7());
    let event_id_typed = cokret_sdk::EventId::new(event_id.clone())
        .map_err(|err| format!("invalid MLS genesis event id: {err:?}"))?;
    let typed_realm_id = cokret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|err| format!("invalid MLS genesis Realm id: {err:?}"))?;
    let membership_frontier = kanban_mls_membership_frontier(&seal_view, &event_id_typed);
    let policy_root = kanban_mls_policy_root(&seal_view, realm_id)?;
    let governance_binding = match circle {
        Some(circle_id) => {
            let typed_circle_id = cokret_sdk::CircleId::new(circle_id.to_owned())
                .map_err(|err| format!("invalid MLS genesis Circle id: {err:?}"))?;
            cokret_sdk::MlsGovernanceBindingPayload::circle(
                typed_realm_id,
                typed_circle_id,
                summary.group_id.clone(),
                0,
                0,
                membership_frontier,
                policy_root,
                cokret_sdk::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
                cokret_sdk::CORE_REDUCER_PROFILE,
            )
        }
        None => cokret_sdk::MlsGovernanceBindingPayload::realm(
            typed_realm_id,
            summary.group_id.clone(),
            0,
            0,
            membership_frontier,
            policy_root,
            cokret_sdk::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            cokret_sdk::CORE_REDUCER_PROFILE,
        ),
    }
    .map_err(|err| format!("MLS genesis governance binding failed: {err}"))?;
    let payload = crate::mls::runtime::build_mls_genesis_payload(
        summary,
        actor_id,
        device_id,
        &governance_binding,
    )
    .map_err(|err| err.user_message())?;
    let mut event = crate::operation::ck_ops::mls_genesis_with_governance(
        realm_id,
        actor_id,
        &summary.group_id,
        &payload,
    )
    .build_sdk_event("yougen")
    .map(Some)
    .map_err(|err| format!("MLS genesis SDK Event conversion failed: {err}"))?;
    if let Some(event) = event.as_mut() {
        event.event_id = event_id_typed;
        if let Some(circle_id) = circle {
            event.effective_scope = Some(circle_effective_scope(realm_id, circle_id)?);
        }
    }
    Ok(event)
}

// pub(crate): the realm_admin epoch-rotation button (YOU-01-009) reuses
// this builder to wrap a forced `self_update_commit` into the canonical
// `ck.mls.commit` event with the governance binding.
pub(crate) fn kanban_mls_commit_event_from_store(
    state_store: &LocalStateStore,
    realm_id: &str,
    actor_id: &str,
    _schedule_hash: &cokret_sdk::Hash,
    commit_envelope: &cokret_sdk::MlsCommitEnvelope,
) -> Result<cokret_sdk::Event, String> {
    kanban_mls_commit_event_from_store_for_effective_scope(
        state_store,
        realm_id,
        None,
        actor_id,
        commit_envelope,
    )
}

pub(crate) fn kanban_mls_commit_event_from_store_for_effective_scope(
    state_store: &LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    commit_envelope: &cokret_sdk::MlsCommitEnvelope,
) -> Result<cokret_sdk::Event, String> {
    kanban_mls_commit_event_from_store_for_effective_scope_with_proposal_refs(
        state_store,
        realm_id,
        circle_id,
        actor_id,
        commit_envelope,
        Vec::new(),
    )
}

pub(crate) fn kanban_mls_commit_event_from_store_for_effective_scope_with_proposal_refs(
    state_store: &LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    commit_envelope: &cokret_sdk::MlsCommitEnvelope,
    proposal_refs: Vec<cokret_sdk::EventId>,
) -> Result<cokret_sdk::Event, String> {
    let circle = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
    let seal_view = state_store.seal_view_for_realm(realm_id);
    // `base_epoch` MUST be the SDK group's PRE-commit epoch so the
    // `next_epoch == base_epoch + 1` invariant holds by construction.
    // `commit_envelope.epoch` is the POST-commit epoch (`self_update_commit`
    // merges the pending commit before reading it), so the pre-commit epoch is
    // exactly one less. Deriving `base_epoch` from `seal_view.mls_epoch`
    // instead — which only refreshes on `/sync` — drifts whenever the local
    // snapshot has advanced past the last server-confirmed epoch, which is what
    // tripped `mls_commit_payload.next_epoch must equal base_epoch + 1`.
    let prev_epoch = commit_envelope.epoch.saturating_sub(1);
    let event_id = format!("ck:event:{}", uuid_v7());
    let event_id_typed = cokret_sdk::EventId::new(event_id.clone())
        .map_err(|err| format!("invalid MLS commit event id: {err:?}"))?;
    let typed_realm_id = cokret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|err| format!("invalid MLS commit Realm id: {err:?}"))?;
    let membership_frontier = kanban_mls_membership_frontier(&seal_view, &event_id_typed);
    let policy_root = kanban_mls_policy_root(&seal_view, realm_id)?;
    let governance_binding = match circle {
        Some(circle_id) => {
            let typed_circle_id = cokret_sdk::CircleId::new(circle_id.to_owned())
                .map_err(|err| format!("invalid MLS commit Circle id: {err:?}"))?;
            cokret_sdk::MlsGovernanceBindingPayload::circle(
                typed_realm_id,
                typed_circle_id,
                commit_envelope.group_id.clone(),
                prev_epoch,
                commit_envelope.epoch,
                membership_frontier,
                policy_root,
                cokret_sdk::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
                cokret_sdk::CORE_REDUCER_PROFILE,
            )
        }
        None => cokret_sdk::MlsGovernanceBindingPayload::realm(
            typed_realm_id,
            commit_envelope.group_id.clone(),
            prev_epoch,
            commit_envelope.epoch,
            membership_frontier,
            policy_root,
            cokret_sdk::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            cokret_sdk::CORE_REDUCER_PROFILE,
        ),
    }
    .map_err(|err| format!("MLS governance binding failed: {err}"))?;
    let payload = cokret_sdk::MlsCommitPayload::new(
        commit_envelope.group_id.clone(),
        prev_epoch,
        kanban_mls_base_epoch_ref_for_scope(&seal_view, realm_id, circle),
        proposal_refs,
        commit_envelope.epoch,
        commit_envelope.commit_digest.clone(),
        governance_binding,
    )
    .map_err(|err| format!("MLS commit payload failed: {err}"))?;
    let mut event =
        crate::operation::ck_ops::mls_commit_with_governance(realm_id, actor_id, &payload)
            .map_err(|err| format!("MLS commit payload failed: {err}"))?
            .build_sdk_event("yougen")
            .map_err(|err| format!("MLS commit SDK Event conversion failed: {err}"))?;
    event.event_id = event_id_typed;
    if let Some(circle_id) = circle {
        event.effective_scope = Some(circle_effective_scope(realm_id, circle_id)?);
    }
    Ok(event)
}

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
        Some(commit_envelope) => Some(kanban_mls_commit_event_from_store(
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
    mut columns: Signal<Vec<KanbanColumn>>,
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

    let mut updated_card = current.clone();
    let mut found = false;
    {
        let mut cols = columns.write();
        for col in cols.iter_mut() {
            if let Some(card) = col.cards.iter_mut().find(|card| card.id == current.id) {
                apply_card_detail_draft(card, &draft);
                updated_card = card.clone();
                found = true;
                break;
            }
        }
    }
    if !found {
        board_status.set(format!(
            "internal: card {} not in board state",
            short_protocol_id(&current.id)
        ));
        return false;
    }
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
            "body": op.content.clone(),
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
    let mls_genesis_op = mls_genesis_op;
    let mls_commit_op = mls_commit_op;
    let submit_event = op;
    spawn(async move {
        // Genesis MUST land before the first commit so the server has the
        // group at epoch 0 before the commit bumps it to 1. A duplicate
        // genesis (`mls_genesis_already_exists`) is treated as success.
        if let Some(genesis_op) = mls_genesis_op {
            let genesis_result = with_authed_api(&base_url, api_token.clone(), |api| async move {
                api.submit_sdk_event(&genesis_op).await
            })
            .await;
            match genesis_result {
                Ok(_) => {
                    state_store
                        .write()
                        .mark_mls_genesis_emitted(realm_id.clone());
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
                        set_card_state_in_columns(&mut columns, &strand_id, CardState::SoftFailed);
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
                api.submit_sdk_event(&commit_op).await
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
                    set_card_state_in_columns(&mut columns, &strand_id, CardState::SoftFailed);
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
            api.submit_sdk_event(&submit_event).await
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
                set_card_state_in_columns(&mut columns, &strand_id, CardState::Accepted);
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
                set_card_state_in_columns(&mut columns, &strand_id, CardState::SoftFailed);
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
