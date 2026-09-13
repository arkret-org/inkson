use super::model::*;
use super::{
    CardAuthorDisplayContext, card_author_display_label, dispatch_card_detail_update,
    json_path_string,
};
use crate::routes::Route;
use crate::state::{LocalStateStore, RawOperationRecord};
use crate::transport::auth::with_authed_api;
use crate::views::helpers::short_protocol_id;

pub(super) fn route_card_strand_id(route: &Route) -> Option<String> {
    match route {
        Route::KanbanTask { task_id, .. } | Route::KanbanBoardTask { task_id, .. } => {
            let task_id = task_id.trim();
            if task_id.is_empty() {
                None
            } else {
                Some(task_id.to_owned())
            }
        }
        _ => None,
    }
}

/// Extract the board Space-container id carried by the board-aware
/// kanban routes. `None` for the board-less routes (plain `/kanban`,
/// `/kanban/<realm>`, and `/kanban/<realm>/task/<strand>`
/// share-link form) where the board must be resolved from projection.
///
/// The URL is untrusted input, so the segment is parsed as a [`SpaceId`] at
/// this boundary and anything else (empty, a holder-local operation id, a
/// malformed id) fails closed to `None` instead of leaking into selection.
pub(super) fn route_board_id(route: &Route) -> Option<arkret_sdk::SpaceId> {
    match route {
        Route::KanbanBoard { board_id, .. } | Route::KanbanBoardTask { board_id, .. } => {
            arkret_sdk::SpaceId::new(board_id.trim()).ok()
        }
        _ => None,
    }
}

/// Build the URL for selecting a board (no card open). Falls back to the
/// board-less `/kanban/<realm>` route when no board is selected yet.
pub(super) fn kanban_board_route(realm_id: &str, board_id: &str) -> Route {
    let realm_id = card_detail_route_realm_id(realm_id);
    let board_id = board_id.trim();
    if board_id.is_empty() {
        Route::KanbanRealm { realm_id }
    } else {
        Route::KanbanBoard {
            realm_id,
            board_id: board_id.to_owned(),
        }
    }
}

/// Build the URL for an open card. Prefers the board-carrying form so a
/// refresh restores the board; falls back to the board-less task route
/// when the board id is unknown.
pub(super) fn kanban_card_task_route(realm_id: &str, board_id: &str, task_id: &str) -> Route {
    let realm_id = card_detail_route_realm_id(realm_id);
    let board_id = board_id.trim();
    let task_id = task_id.trim().to_owned();
    if board_id.is_empty() {
        Route::KanbanTask { realm_id, task_id }
    } else {
        Route::KanbanBoardTask {
            realm_id,
            board_id: board_id.to_owned(),
            task_id,
        }
    }
}

pub(super) fn card_matches_strand_id(card: &KanbanCard, strand_id: &str) -> bool {
    let strand_id = strand_id.trim();
    !strand_id.is_empty() && (card.id == strand_id || card.primary_strand_id == strand_id)
}

pub(super) fn card_discussion_target_ready(card: &KanbanCard) -> bool {
    arkret_sdk::StrandId::new(card.primary_strand_id.clone()).is_ok()
}

pub(super) fn find_card_by_strand_id(
    columns: &[KanbanColumn],
    strand_id: &str,
) -> Option<KanbanCard> {
    columns
        .iter()
        .flat_map(|column| column.cards.iter())
        .find(|card| card_matches_strand_id(card, strand_id))
        .cloned()
}

pub(super) fn compact_timestamp_label(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "time unknown".to_owned();
    }
    if let Some((date, rest)) = trimmed.split_once('T') {
        let time = rest.trim_end_matches('Z').split('.').next().unwrap_or(rest);
        let hhmm = time.split(':').take(2).collect::<Vec<_>>().join(":");
        if !date.is_empty() && hhmm.len() >= 4 {
            return format!("{date} {hhmm}");
        }
    }
    trimmed.to_owned()
}

pub(super) const SYNTHESIS_ENTRY_SEPARATOR: &str = "\n\n---\n\n";

pub(super) fn split_synthesis_entry_bodies(value: &str) -> Vec<String> {
    let mut entries = Vec::<String>::new();
    let mut current = Vec::<String>::new();
    for line in value.lines() {
        if line.trim() == "---" {
            let body = current.join("\n").trim().to_owned();
            if !body.is_empty() {
                entries.push(body);
            }
            current.clear();
        } else {
            current.push(line.to_owned());
        }
    }
    let body = current.join("\n").trim().to_owned();
    if !body.is_empty() {
        entries.push(body);
    }
    entries
}

pub(super) fn join_synthesis_entry_bodies(entries: Vec<String>) -> String {
    entries
        .into_iter()
        .map(|entry| entry.trim().to_owned())
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>()
        .join(SYNTHESIS_ENTRY_SEPARATOR)
}

pub(super) fn synthesis_body_after_entry_edit(
    entries: &[CardSynthesisTrackEntry],
    target_entry_id: Option<&str>,
    replacement_body: &str,
) -> String {
    let replacement = replacement_body.trim();
    let mut found_target = false;
    let mut bodies = entries
        .iter()
        .filter_map(|entry| {
            if target_entry_id == Some(entry.id.as_str()) {
                found_target = true;
                (!replacement.is_empty()).then(|| replacement.to_owned())
            } else {
                let body = entry.body.trim();
                (!body.is_empty()).then(|| body.to_owned())
            }
        })
        .collect::<Vec<_>>();
    if !replacement.is_empty() && (target_entry_id.is_none() || !found_target) {
        bodies.push(replacement.to_owned());
    }
    join_synthesis_entry_bodies(bodies)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn reset_card_detail_edit(
    current: &KanbanCard,
    mut card_edit_title: Signal<String>,
    mut card_edit_description: Signal<String>,
    mut card_edit_body: Signal<String>,
    mut card_edit_synthesis: Signal<String>,
    mut card_edit_synthesis_target_id: Signal<Option<String>>,
    mut card_edit_labels: Signal<String>,
    mut card_edit_assignee: Signal<String>,
    mut card_edit_due: Signal<String>,
    mut editing_card_detail: Signal<bool>,
    mut card_detail_actions_open: Signal<bool>,
    mut card_synthesis_history_open_id: Signal<Option<String>>,
    mut card_synthesis_selected_revision_id: Signal<Option<String>>,
    mut card_detail_edit_status: Signal<String>,
) {
    let draft = card_detail_draft_from_card(current);
    card_edit_title.set(draft.title);
    card_edit_description.set(draft.description);
    card_edit_body.set(draft.description_body);
    card_edit_synthesis.set(draft.synthesis);
    card_edit_synthesis_target_id.set(None);
    card_edit_labels.set(draft.labels.join(", "));
    card_edit_assignee.set(draft.assignee);
    card_edit_due.set(draft.due);
    editing_card_detail.set(false);
    card_detail_actions_open.set(false);
    card_synthesis_history_open_id.set(None);
    card_synthesis_selected_revision_id.set(None);
    card_detail_edit_status.set(String::new());
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn save_card_detail_edit(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    device_id: String,
    current: KanbanCard,
    synthesis_entries: Vec<CardSynthesisTrackEntry>,
    // R4: three-state security signal (see `kanban_plaintext_block_reason`).
    scope_security_encrypted: Option<bool>,
    sidecar_track_write: Option<SidecarTrackWriteContext>,
    card_edit_scope: Signal<CardEditScope>,
    card_edit_title: Signal<String>,
    card_edit_description: Signal<String>,
    card_edit_body: Signal<String>,
    card_edit_synthesis: Signal<String>,
    card_edit_synthesis_target_id: Signal<Option<String>>,
    card_edit_labels: Signal<String>,
    card_edit_assignee: Signal<String>,
    card_edit_due: Signal<String>,
    mut editing_card_detail: Signal<bool>,
    mut card_detail_actions_open: Signal<bool>,
    mut card_detail_edit_status: Signal<String>,
    selected_card: Signal<Option<KanbanCard>>,
    state_store: SyncSignal<LocalStateStore>,
    mut board_status: Signal<String>,
) {
    let Some(active_account) = crate::app::SessionContext::get()
        .active_account
        .read()
        .clone()
    else {
        card_detail_edit_status.set("Active account is unavailable".to_owned());
        return;
    };
    let authority = active_account.authority;
    let account_device_id = active_account.device_id;
    card_detail_edit_status.set("Saving...".to_owned());
    let edit_scope = card_edit_scope();
    if sidecar_track_write.is_some() && edit_scope != CardEditScope::Synthesis {
        card_detail_edit_status
            .set("Private Sidecar editing is available only on the Synthesis track".to_owned());
        return;
    }
    let synthesis_target_id = card_edit_synthesis_target_id();
    let (draft, synthesis_revision) = card_detail_draft_for_edit_scope(
        &current,
        edit_scope,
        &synthesis_entries,
        synthesis_target_id.as_deref(),
        &card_edit_title(),
        &card_edit_description(),
        &card_edit_body(),
        &card_edit_synthesis(),
        &card_edit_labels(),
        &card_edit_assignee(),
        &card_edit_due(),
    );
    let needs_encryption =
        match super::card_patch::card_detail_patch_needs_encryption(&current, &draft) {
            Ok(value) => value,
            Err(error) => {
                card_detail_edit_status.set(error);
                return;
            }
        };
    let encrypted_realm_write = needs_encryption
        && sidecar_track_write.is_none()
        && current
            .security_encrypted
            .unwrap_or_else(|| scope_security_encrypted.unwrap_or(true));
    if encrypted_realm_write
        && !encrypted_realm_write_mls_ready(&state_store.read(), &realm_id, &authority)
    {
        let session_credential = token();
        card_detail_edit_status.set("Restoring encrypted Realm state before saving...".to_owned());
        spawn(async move {
            match recover_mls_checkpoint_for_encrypted_write(
                &base_url,
                &session_credential,
                &realm_id,
                &actor_id,
                &authority,
                &account_device_id,
                state_store,
            )
            .await
            {
                Ok(()) => {
                    if dispatch_card_detail_update(
                        base_url,
                        token,
                        realm_id,
                        actor_id,
                        device_id,
                        current,
                        draft,
                        scope_security_encrypted,
                        sidecar_track_write,
                        synthesis_target_id,
                        synthesis_revision,
                        selected_card,
                        state_store,
                        board_status,
                    )
                    .await
                    {
                        card_detail_edit_status.set(String::new());
                        editing_card_detail.set(false);
                        card_detail_actions_open.set(false);
                    } else {
                        let status = board_status();
                        card_detail_edit_status.set(if status.trim().is_empty() {
                            "Unable to save changes.".to_owned()
                        } else {
                            status
                        });
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        realm = %realm_id,
                        %error,
                        "encrypted Kanban write readiness recovery failed"
                    );
                    board_status.set(error.clone());
                    card_detail_edit_status.set(error);
                }
            }
        });
        return;
    }

    if dispatch_card_detail_update(
        base_url,
        token,
        realm_id,
        actor_id,
        device_id,
        current,
        draft,
        scope_security_encrypted,
        sidecar_track_write,
        synthesis_target_id,
        synthesis_revision,
        selected_card,
        state_store,
        board_status,
    )
    .await
    {
        card_detail_edit_status.set(String::new());
        editing_card_detail.set(false);
        card_detail_actions_open.set(false);
    } else {
        let status = board_status();
        card_detail_edit_status.set(if status.trim().is_empty() {
            "Unable to save changes.".to_owned()
        } else {
            status
        });
    }
}

/// Make a Realm-scoped encrypted write independent of the timing of the
/// background MLS effects. A Save click is itself a concrete readiness demand:
/// fetch a pending Welcome, restore a decryptable account history backup, or
/// finish creator genesis before retrying the exact draft the user submitted.
async fn recover_mls_checkpoint_for_encrypted_write(
    base_url: &str,
    session_credential: &str,
    realm_id: &str,
    actor_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    state_store: SyncSignal<LocalStateStore>,
) -> Result<(), String> {
    // The account MLS secret is an IndexedDB-only key on wasm; before that
    // tier finishes its async boot the sync store surface reports it missing.
    // Await initialization first so a Save clicked early cannot misdiagnose a
    // healthy device as "no account MLS secret".
    #[cfg(target_arch = "wasm32")]
    if let Err(error) = crate::secure_key_store::ensure_wasm_secure_key_store_ready("inkson").await
    {
        tracing::warn!(
            %error,
            "IndexedDB secure store unavailable before encrypted write recovery"
        );
    }
    if encrypted_realm_write_mls_ready(&state_store.read(), realm_id, authority) {
        return Ok(());
    }

    let mut failures = Vec::new();
    let store_handle = crate::app::runtime_adapter::state_store_handle(state_store);
    // Current-sync can lag behind a newly accepted Realm, so the local
    // authority-root cell is an optimization rather than a prerequisite. If
    // it is absent, let creator bootstrap resolve the exact immutable
    // ak.realm.create Event from the Station; invitees still skip this path as
    // soon as their projected root names another actor.
    let api = crate::transport::auth::authed_api_ready(base_url, session_credential.to_owned())
        .await
        .map_err(|error| format!("MLS bootstrap transport: {error}"))?;
    let is_creator = crate::mls::creator_bootstrap::should_resume_creator_genesis(
        &api,
        &store_handle,
        realm_id,
        authority,
    )
    .await?;
    if is_creator {
        if let Err(error) = crate::mls::creator_bootstrap::ensure_creator_realm_mls_genesis(
            &api,
            &store_handle,
            realm_id,
            authority,
            device_id,
        )
        .await
        {
            failures.push(format!("creator bootstrap: {error}"));
        }
    } else {
        match crate::app::bootstrap_mls_welcome_for_realm(
            base_url.to_owned(),
            session_credential.to_owned(),
            actor_id.to_owned(),
            authority.clone(),
            device_id.clone(),
            realm_id.to_owned(),
            &store_handle,
            None,
        )
        .await
        {
            Ok(_) => {}
            Err(error) => failures.push(format!("Welcome: {error}")),
        }
    }
    if encrypted_realm_write_mls_ready(&state_store.read(), realm_id, authority) {
        return Ok(());
    }

    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let has_local_account_secret = matches!(
        crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), authority),
        Ok(Some(_))
    );
    if has_local_account_secret {
        let actor_for_fetch = actor_id.to_owned();
        let device_for_fetch = device_id.to_string();
        match with_authed_api(
            base_url,
            session_credential.to_owned(),
            move |api| async move {
                crate::mls::account_recovery::fetch_mls_restore_payload_with_unlock_proof(
                    &api,
                    &actor_for_fetch,
                    &device_for_fetch,
                )
                .await
            },
        )
        .await
        {
            Ok(payload) => {
                let report =
                    crate::mls::account_recovery::restore_mls_history_with_local_secret_from_payload(
                        &payload,
                        &store_handle,
                        secure_store.as_ref(),
                        authority,
                        actor_id,
                    )
                    .await;
                if report.failed > 0 {
                    failures.push(format!(
                        "history backup: {}",
                        report.first_error.as_deref().unwrap_or("restore failed")
                    ));
                }
            }
            Err(error) => failures.push(format!("history backup: {}", error.display())),
        }
    }
    if encrypted_realm_write_mls_ready(&state_store.read(), realm_id, authority) {
        return Ok(());
    }

    // Recovery may have restored key material. Re-read it without conflating
    // account-root recovery with device approval or a pending Welcome.
    let has_local_account_secret = matches!(
        crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), authority),
        Ok(Some(_))
    );
    const NO_SECRET_HINT: &str = "This device is missing the account encryption key. Restore the original key using account recovery; approving the device again or receiving a Welcome does not restore it.";
    if failures.is_empty() {
        if has_local_account_secret {
            Err(
                "No pending Welcome or matching MLS history snapshot exists on the server for this Realm."
                    .to_owned(),
            )
        } else {
            Err(NO_SECRET_HINT.to_owned())
        }
    } else {
        let mut message = format!(
            "Could not restore this Realm's encrypted state ({}).",
            failures.join("; ")
        );
        if !has_local_account_secret {
            message.push(' ');
            message.push_str(NO_SECRET_HINT);
        }
        Err(message)
    }
}

fn encrypted_realm_write_mls_ready(
    state_store: &LocalStateStore,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
) -> bool {
    // A snapshot and account secret alone are only executable key material;
    // they do not prove that the snapshot's Genesis/Commit won governance.
    // In particular, the creator flow can be interrupted after Genesis submit
    // but before its checkpoint is advanced. Treat that state as recoverable,
    // not ready, so Save re-enters the bootstrap convergence path instead of
    // failing later while retaining the epoch history secret.
    if state_store
        .accepted_current_realm_mls_transition_evidence(realm_id)
        .is_err()
    {
        return false;
    }
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    matches!(
        crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), authority),
        Ok(Some(_))
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn card_detail_draft_for_edit_scope(
    current: &KanbanCard,
    edit_scope: CardEditScope,
    synthesis_entries: &[CardSynthesisTrackEntry],
    synthesis_target_id: Option<&str>,
    title: &str,
    description: &str,
    description_body: &str,
    synthesis: &str,
    labels: &str,
    _assignee: &str,
    due: &str,
) -> (CardDetailDraft, Option<String>) {
    let mut draft = card_detail_draft_from_card(current);
    match edit_scope {
        CardEditScope::Summary => {
            draft.title = title.trim().to_owned();
            draft.description = description.trim().to_owned();
            draft.labels = parse_card_labels(labels);
            draft.due = due.trim().to_owned();
            (draft, None)
        }
        CardEditScope::Description => {
            draft.description_body = description_body.trim().to_owned();
            (draft, None)
        }
        CardEditScope::Synthesis => {
            let revision_body = synthesis.trim().to_owned();
            draft.synthesis = synthesis_body_after_entry_edit(
                synthesis_entries,
                synthesis_target_id,
                &revision_body,
            );
            (draft, Some(revision_body))
        }
        CardEditScope::Calendar => (draft, None),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn save_card_due_edit(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    device_id: String,
    current: KanbanCard,
    due_value: String,
    scope_security_encrypted: Option<bool>,
    mut due_picker_open: Signal<bool>,
    mut due_edit_status: Signal<String>,
    selected_card: Signal<Option<KanbanCard>>,
    state_store: SyncSignal<LocalStateStore>,
    board_status: Signal<String>,
) -> bool {
    let mut draft = card_detail_draft_from_card(&current);
    draft.due = due_value.trim().to_owned();
    due_edit_status.set("Saving...".to_owned());
    if dispatch_card_detail_update(
        base_url,
        token,
        realm_id,
        actor_id,
        device_id,
        current,
        draft,
        scope_security_encrypted,
        None,
        None,
        None,
        selected_card,
        state_store,
        board_status,
    )
    .await
    {
        due_edit_status.set(String::new());
        due_picker_open.set(false);
        true
    } else {
        let status = board_status();
        due_edit_status.set(if status.trim().is_empty() {
            "Unable to save due date.".to_owned()
        } else {
            status
        });
        false
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn save_card_calendar_edit(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    device_id: String,
    current: KanbanCard,
    calendar: CalendarCardFields,
    scope_security_encrypted: Option<bool>,
    mut editing_card_detail: Signal<bool>,
    mut card_detail_actions_open: Signal<bool>,
    mut card_detail_edit_status: Signal<String>,
    selected_card: Signal<Option<KanbanCard>>,
    state_store: SyncSignal<LocalStateStore>,
    board_status: Signal<String>,
) -> bool {
    let mut draft = card_detail_draft_from_card(&current);
    draft.calendar = calendar;
    card_detail_edit_status.set("Saving calendar...".to_owned());
    if dispatch_card_detail_update(
        base_url,
        token,
        realm_id,
        actor_id,
        device_id,
        current,
        draft,
        scope_security_encrypted,
        None,
        None,
        None,
        selected_card,
        state_store,
        board_status,
    )
    .await
    {
        card_detail_edit_status.set(String::new());
        editing_card_detail.set(false);
        card_detail_actions_open.set(false);
        true
    } else {
        let status = board_status();
        card_detail_edit_status.set(if status.trim().is_empty() {
            "Unable to save calendar.".to_owned()
        } else {
            status
        });
        false
    }
}

/// Queued op-log record for one calendar RSVP write; field order matches
/// the wire layout the previous `json!` literal produced, with `body` read
/// back through its typed marker payload.
#[derive(serde::Serialize)]
struct QueuedCalendarRsvpRecord<'a> {
    kind: &'a str,
    operation_id: &'a str,
    actor_id: String,
    created_at: String,
    write_state: &'static str,
    body: arkret_sdk::RsvpSetPayload,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch_calendar_rsvp(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    card: KanbanCard,
    status: &'static str,
    occurrence: String,
    mut state_store: SyncSignal<LocalStateStore>,
    mut board_status: Signal<String>,
) {
    if card.security_encrypted == Some(true) {
        board_status.set(
            "cannot build RSVP: encrypted calendar responses require the Realm MLS key".to_owned(),
        );
        return;
    }
    if card.state != CardState::Synced {
        board_status.set("cannot build RSVP: resolve the current Card first".to_owned());
        return;
    }
    let Some((_, source_event)) = card.authoring_basis.clone() else {
        board_status.set("cannot build RSVP: waiting for the complete current Card".to_owned());
        return;
    };
    board_status.set("resolving the observed calendar schedule".to_owned());
    let api_token = token();
    let submit_token = api_token.clone();
    let strand_id = card.primary_strand_id.clone();
    let calendar = card.calendar.clone();
    let build_base = base_url.clone();
    let build_realm_id = realm_id.clone();
    let build_actor_id = actor_id.clone();
    let Some(digest_suite) = state_store.read().station_realm_digest_suite(&realm_id) else {
        board_status.set("cannot build RSVP: waiting for the Realm Station frontier".to_owned());
        return;
    };
    spawn(async move {
        let built = with_authed_api(&build_base, api_token, |api| async move {
            // Resolve only the frozen object's source closure. Never attach a
            // newly observed frontier to the calendar value captured by the UI.
            let mut pending = std::collections::BTreeSet::from([source_event.event_digest()]);
            let mut seen = std::collections::BTreeSet::new();
            let mut events = Vec::new();
            while !pending.is_empty() {
                if seen.len() + pending.len() > 4096 {
                    anyhow::bail!("calendar source closure exceeds the local authoring budget");
                }
                let batch = pending.iter().take(64).cloned().collect::<Vec<_>>();
                for digest in &batch {
                    pending.remove(digest);
                }
                let outcome = api
                    .http()
                    .events_resolve(&arkret_sdk::EventsResolveRequestBody {
                        event_ids: Vec::new(),
                        event_digests: batch.clone(),
                        include_payload: Some(true),
                        history_traversal_access: None,
                        max_response_bytes: Some(8_388_608),
                    })
                    .await?;
                if !outcome.missing.is_empty() || !outcome.unauthorized.is_empty() {
                    anyhow::bail!("calendar source closure is unavailable");
                }
                let mut returned = std::collections::BTreeSet::new();
                for event in outcome.events {
                    let digest =
                        arkret_sdk::Hash::new(event.event_digest_with_digest_suite(digest_suite)?)?;
                    if !batch.contains(&digest) || !returned.insert(digest.clone()) {
                        anyhow::bail!("calendar source resolve returned an unexpected Event");
                    }
                    seen.insert(digest);
                    if event.kind != arkret_sdk::EventKind::StrandCreate {
                        for reference in &event.causal_refs {
                            if !seen.contains(reference) {
                                pending.insert(reference.clone());
                            }
                        }
                    }
                    events.push(event);
                }
                pending.retain(|digest| !seen.contains(digest));
                if returned.len() != batch.len() {
                    anyhow::bail!("calendar source resolve returned an incomplete batch");
                }
            }
            let schedule_winner = calendar_schedule_revision_winner_at_source(
                &events,
                &strand_id,
                digest_suite,
                &source_event,
            )?;
            // The actor frontier and HLC belong to the authoring boundary; the
            // builder only states what the user chose.
            calendar_rsvp_operation(
                &build_realm_id,
                &build_actor_id,
                &strand_id,
                status,
                &occurrence,
                &calendar,
                vec![schedule_winner],
            )
        })
        .await;
        match built {
            Ok(event) => {
                let operation_id = event.local_operation_id().to_string();
                let kind = event.kind().as_str().to_owned();
                let body = match event.typed_payload::<arkret_wire::event_spec::RsvpSet>() {
                    Ok(body) => body,
                    Err(err) => {
                        board_status.set(format!("cannot queue RSVP: {err:#}"));
                        return;
                    }
                };
                let record = match serde_json::to_value(QueuedCalendarRsvpRecord {
                    kind: &kind,
                    operation_id: &operation_id,
                    actor_id: event.actor_id().to_string(),
                    created_at: arkret_sdk::canonical::format_timestamp_canonical(
                        event.created_at(),
                    ),
                    write_state: "queued",
                    body: body.clone(),
                }) {
                    Ok(record) => record,
                    Err(err) => {
                        board_status.set(format!("cannot queue RSVP: {err}"));
                        return;
                    }
                };
                state_store.write().enqueue_local_projection_command(
                    operation_id.clone(),
                    Some(realm_id.clone()),
                    record,
                );
                board_status.set(format!(
                    "submitting RSVP {}",
                    short_protocol_id(&operation_id)
                ));
                let submitted = with_authed_api(&base_url, submit_token, |api| async move {
                    api.event_submitter()?.submit_sdk_event(&event).await
                })
                .await;
                let Ok(response) = submitted else {
                    board_status.set(format!("RSVP failed: {submitted:#?}"));
                    return;
                };
                let accepted_event_id = response.event_id.clone();
                let causal_refs = body
                    .entry
                    .schedule_basis_refs
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                state_store.write().upsert_raw_operation(
                    accepted_event_id.clone(),
                    Some(realm_id),
                    serde_json::json!({
                        "kind": kind,
                        "operation_id": accepted_event_id,
                        "event_id": response.event_id,
                        "local_operation_idempotency_alias": operation_id,
                        "actor_id": actor_id,
                        "created_at": arkret_sdk::canonical::format_timestamp_canonical(
                            crate::clock::now_utc()
                        ),
                        "write_state": "synced",
                        "body": body,
                        "causal_refs": causal_refs.clone(),
                        "locally_observed_schedule_winner": causal_refs[0],
                    }),
                );
                board_status.set(format!(
                    "{} accepted as {}",
                    kind,
                    short_protocol_id(&response.event_id)
                ));
            }
            Err(err) => {
                board_status.set(format!("cannot build RSVP: {err:#?}"));
            }
        }
    });
}

pub(super) fn projection_synthesis_revision(
    card: &KanbanCard,
    index: usize,
    body: String,
    state_store: &LocalStateStore,
    author_context: Option<CardAuthorDisplayContext<'_>>,
) -> CardSynthesisRevision {
    // This is the PROJECTION FALLBACK: a synthesis entry from the card's current
    // decrypted state that could NOT be tied to a specific authoring operation
    // (typically a co-author's entry synced to this device without its raw
    // `ak.strand.update` op, or whose decrypted body didn't match the replay).
    // The card-level `updated_by` is only the LATEST editor, so attributing
    // every such entry to it mis-labels other authors' entries as the last
    // editor: a cross-member misattribution bug. Only attribute when
    // the card is unambiguously single-author; otherwise leave it unattributed
    // so the UI shows "Unknown author" rather than a confidently-wrong name.
    let created = card.created_by.trim();
    let updated = card.updated_by.trim();
    let actor_id = if updated.is_empty() {
        created.to_owned()
    } else if created.is_empty() || created == updated {
        updated.to_owned()
    } else {
        // Multi-author card, no per-entry provenance: do not guess.
        String::new()
    };
    let timestamp = if !card.updated_at.trim().is_empty() {
        card.updated_at.clone()
    } else {
        card.created_at.clone()
    };
    let author_label = card_author_display_label(state_store, author_context, &actor_id);
    CardSynthesisRevision {
        id: format!("{}:projection-synthesis:{index}", card.id),
        body,
        actor_id,
        author_label,
        timestamp_label: compact_timestamp_label(&timestamp),
        sort_key: timestamp,
    }
}

fn raw_operation_synthesis_timestamp(record: &RawOperationRecord) -> String {
    let payload = &record.payload;
    json_path_string(Some(payload), &["created_at"])
        .or_else(|| json_path_string(Some(payload), &["body", "created_at"]))
        .or_else(|| json_path_string(Some(payload), &["payload", "created_at"]))
        .unwrap_or_else(|| arkret_sdk::canonical::format_timestamp_canonical(record.received_at))
}

fn raw_operation_synthesis_actor_id(record: &RawOperationRecord) -> String {
    let payload = &record.payload;
    [
        payload.get("actor_id"),
        payload.get("sender_actor_id"),
        payload.pointer("/body/actor_id"),
        payload.pointer("/body/sender_actor_id"),
        payload.pointer("/payload/actor_id"),
        payload.pointer("/payload/sender_actor_id"),
    ]
    .into_iter()
    .flatten()
    .find_map(crate::state::projection::message_ops::actor_principal_from_value)
    .unwrap_or_default()
}

fn synthesis_revision_for_raw_body(
    record: &RawOperationRecord,
    body: String,
    state_store: &LocalStateStore,
    author_context: Option<CardAuthorDisplayContext<'_>>,
) -> CardSynthesisRevision {
    let actor_id = raw_operation_synthesis_actor_id(record);
    let timestamp = raw_operation_synthesis_timestamp(record);
    let author_label = card_author_display_label(state_store, author_context, &actor_id);
    CardSynthesisRevision {
        id: record.operation_id.clone(),
        body,
        actor_id,
        author_label,
        timestamp_label: compact_timestamp_label(&timestamp),
        sort_key: timestamp,
    }
}

fn apply_synthesis_full_value_to_history(
    card_id: &str,
    record: &RawOperationRecord,
    next_value: &str,
    explicit_entry_id: Option<&str>,
    grouped: &mut std::collections::BTreeMap<String, Vec<CardSynthesisRevision>>,
    replay_bodies: &mut Vec<String>,
    replay_entry_ids: &mut Vec<String>,
    state_store: &LocalStateStore,
    author_context: Option<CardAuthorDisplayContext<'_>>,
    add_revisions: bool,
) {
    let next_bodies = split_synthesis_entry_bodies(next_value);
    if next_bodies.is_empty() {
        replay_bodies.clear();
        replay_entry_ids.clear();
        return;
    }

    let mut next_entry_ids = Vec::with_capacity(next_bodies.len());
    for (index, next_body) in next_bodies.iter().enumerate() {
        let entry_id = replay_entry_ids
            .get(index)
            .cloned()
            .or_else(|| {
                explicit_entry_id
                    .filter(|_| index + 1 == next_bodies.len())
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_else(|| format!("{card_id}:synthesis:{index}"));
        let changed = replay_bodies.get(index) != Some(next_body);
        if add_revisions && changed {
            grouped
                .entry(entry_id.clone())
                .or_default()
                .push(synthesis_revision_for_raw_body(
                    record,
                    next_body.clone(),
                    state_store,
                    author_context,
                ));
        }
        next_entry_ids.push(entry_id);
    }

    *replay_bodies = next_bodies;
    *replay_entry_ids = next_entry_ids;
}

pub(super) fn synthesis_entry_from_revisions(
    entry_id: String,
    mut revisions: Vec<CardSynthesisRevision>,
) -> Option<CardSynthesisTrackEntry> {
    revisions.sort_by(|left, right| {
        left.sort_key
            .cmp(&right.sort_key)
            .then(left.id.cmp(&right.id))
    });
    revisions.dedup_by(|left, right| left.id == right.id);
    let latest = revisions.last()?.clone();
    Some(CardSynthesisTrackEntry {
        id: entry_id,
        body: latest.body.clone(),
        actor_id: latest.actor_id.clone(),
        author_label: latest.author_label.clone(),
        timestamp_label: latest.timestamp_label.clone(),
        sort_key: latest.sort_key.clone(),
        edited: revisions.len() > 1,
        revisions,
    })
}

#[cfg(test)]
pub(super) fn card_synthesis_track_entries(
    card: &KanbanCard,
    raw_operations: &[RawOperationRecord],
    state_store: &LocalStateStore,
) -> Vec<CardSynthesisTrackEntry> {
    card_synthesis_track_entries_with_author_context(card, raw_operations, state_store, None)
}

#[cfg(test)]
pub(super) fn card_synthesis_track_entries_with_author_context(
    card: &KanbanCard,
    raw_operations: &[RawOperationRecord],
    state_store: &LocalStateStore,
    author_context: Option<CardAuthorDisplayContext<'_>>,
) -> Vec<CardSynthesisTrackEntry> {
    card_synthesis_track_entries_with_author_context_and_decrypt(
        card,
        raw_operations,
        state_store,
        author_context,
        None,
    )
}

pub(super) fn card_synthesis_track_entries_with_author_context_and_decrypt(
    card: &KanbanCard,
    raw_operations: &[RawOperationRecord],
    state_store: &LocalStateStore,
    author_context: Option<CardAuthorDisplayContext<'_>>,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> Vec<CardSynthesisTrackEntry> {
    let mut grouped = std::collections::BTreeMap::<String, Vec<CardSynthesisRevision>>::new();
    let target_strand_id = card.id.trim();
    let mut ordered = raw_operations
        .iter()
        .filter(|record| {
            raw_operation_strand_update_target_id(&record.payload).as_deref()
                == Some(target_strand_id)
        })
        .filter_map(|record| {
            let update = local_card_update_from_raw_operation(record, decrypt_ctx)?;
            Some((record, update))
        })
        .collect::<Vec<_>>();
    ordered.sort_by(|(left_record, _), (right_record, _)| {
        raw_operation_synthesis_timestamp(left_record)
            .cmp(&raw_operation_synthesis_timestamp(right_record))
            .then(left_record.operation_id.cmp(&right_record.operation_id))
    });

    let mut replay_bodies = Vec::<String>::new();
    let mut replay_entry_ids = Vec::<String>::new();
    for (record, update) in ordered {
        let explicit_body = json_path_string(Some(&record.payload), &["synthesis_revision_body"])
            .map(|body| body.trim().to_owned())
            .filter(|body| !body.is_empty());
        let explicit_entry_id = json_path_string(Some(&record.payload), &["synthesis_entry_id"]);
        if let Some(body) = explicit_body {
            let entry_id = explicit_entry_id
                .clone()
                .unwrap_or_else(|| format!("{}:synthesis", update.strand_id));
            grouped
                .entry(entry_id.clone())
                .or_default()
                .push(synthesis_revision_for_raw_body(
                    record,
                    body,
                    state_store,
                    author_context,
                ));
            if let Some(PrivateFieldOverlay::Set(full_value)) = update.synthesis {
                apply_synthesis_full_value_to_history(
                    &card.id,
                    record,
                    &full_value,
                    Some(&entry_id),
                    &mut grouped,
                    &mut replay_bodies,
                    &mut replay_entry_ids,
                    state_store,
                    author_context,
                    false,
                );
            }
            continue;
        }
        match update.synthesis {
            Some(PrivateFieldOverlay::Set(full_value)) => {
                apply_synthesis_full_value_to_history(
                    &card.id,
                    record,
                    &full_value,
                    explicit_entry_id.as_deref(),
                    &mut grouped,
                    &mut replay_bodies,
                    &mut replay_entry_ids,
                    state_store,
                    author_context,
                    true,
                );
            }
            Some(PrivateFieldOverlay::Unset) => {
                replay_bodies.clear();
                replay_entry_ids.clear();
            }
            _ => {}
        }
    }
    let mut raw_entries = grouped
        .into_iter()
        .filter_map(|(entry_id, revisions)| synthesis_entry_from_revisions(entry_id, revisions))
        .collect::<Vec<_>>();
    raw_entries.sort_by(|left, right| {
        left.sort_key
            .cmp(&right.sort_key)
            .then(left.id.cmp(&right.id))
    });

    let current_bodies = split_synthesis_entry_bodies(&card.synthesis);
    if current_bodies.is_empty() {
        return raw_entries;
    }

    let mut raw_used = vec![false; raw_entries.len()];
    let mut entries = Vec::<CardSynthesisTrackEntry>::new();
    let single_entry_history = current_bodies.len() == 1 && raw_entries.len() == 1;
    for (index, current_body) in current_bodies.into_iter().enumerate() {
        let current_trimmed = current_body.trim().to_owned();
        let matched_index = raw_entries
            .iter()
            .enumerate()
            .find_map(|(raw_index, entry)| {
                (!raw_used[raw_index] && entry.body.trim() == current_trimmed).then_some(raw_index)
            })
            .or_else(|| single_entry_history.then_some(0));

        if let Some(raw_index) = matched_index {
            raw_used[raw_index] = true;
            let mut entry = raw_entries[raw_index].clone();
            if entry.body.trim() != current_trimmed {
                entry.revisions.push(projection_synthesis_revision(
                    card,
                    index,
                    current_body,
                    state_store,
                    author_context,
                ));
                if let Some(rebuilt) =
                    synthesis_entry_from_revisions(entry.id.clone(), entry.revisions.clone())
                {
                    entry = rebuilt;
                }
            }
            entries.push(entry);
        } else {
            let revision = projection_synthesis_revision(
                card,
                index,
                current_body,
                state_store,
                author_context,
            );
            if let Some(entry) = synthesis_entry_from_revisions(
                format!("{}:synthesis:{index}", card.id),
                vec![revision],
            ) {
                entries.push(entry);
            }
        }
    }
    entries
}

pub(super) fn card_detail_route_realm_id(realm_id: &str) -> String {
    let realm_id = realm_id.trim();
    if realm_id.is_empty() {
        DEMO_BOARD_SPACE_ID.to_owned()
    } else {
        realm_id.to_owned()
    }
}

pub(super) fn kanban_card_detail_board_route(
    realm_id: &str,
    board_id: Option<&arkret_sdk::SpaceId>,
) -> Route {
    let realm_id = realm_id.trim();
    if realm_id.is_empty() {
        Route::Kanban
    } else {
        kanban_board_route(
            realm_id,
            board_id.map(arkret_sdk::SpaceId::as_str).unwrap_or(""),
        )
    }
}

pub(super) fn card_detail_tab_slug(tab: CardDetailContentTab) -> &'static str {
    match tab {
        CardDetailContentTab::Description => "description",
        CardDetailContentTab::Synthesis => "synthesis",
        CardDetailContentTab::Discussion => "discussion",
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
pub(super) fn card_detail_tab_from_slug(value: &str) -> Option<CardDetailContentTab> {
    match value.trim().to_ascii_lowercase().as_str() {
        "description" => Some(CardDetailContentTab::Description),
        "synthesis" => Some(CardDetailContentTab::Synthesis),
        "discussion" => Some(CardDetailContentTab::Discussion),
        _ => None,
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
pub(super) fn card_detail_tab_from_href(href: &str) -> Option<CardDetailContentTab> {
    let url = url::Url::parse(href).ok()?;
    url.query_pairs()
        .find_map(|(key, value)| (key == "tab").then(|| card_detail_tab_from_slug(&value)))
        .flatten()
}

#[cfg(target_arch = "wasm32")]
pub(super) fn card_detail_tab_from_current_url() -> CardDetailContentTab {
    web_sys::window()
        .and_then(|window| window.location().href().ok())
        .as_deref()
        .and_then(card_detail_tab_from_href)
        .unwrap_or_default()
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn card_detail_tab_from_current_url() -> CardDetailContentTab {
    CardDetailContentTab::default()
}

pub(super) fn replace_card_detail_tab_query(tab: CardDetailContentTab) {
    let Ok(encoded_slug) = serde_json::to_string(card_detail_tab_slug(tab)) else {
        return;
    };
    let script = format!(
        r#"
(() => {{
  const tab = {encoded_slug};
  const url = new URL(window.location.href);
  if (!url.pathname.includes("/task/")) {{
    return;
  }}
  url.searchParams.set("tab", tab);
  window.history.replaceState(null, "", `${{url.pathname}}${{url.search}}${{url.hash}}`);
}})();
"#
    );
    let _ = document::eval(&script);
}

pub(super) fn strand_detail_deep_link_path(realm_id: &str, strand_id: &str) -> String {
    format!(
        "/kanban/{}/task/{}",
        card_detail_route_realm_id(realm_id),
        strand_id.trim()
    )
}

pub(super) fn strand_detail_deep_link_path_with_tab(
    realm_id: &str,
    strand_id: &str,
    tab: CardDetailContentTab,
) -> String {
    format!(
        "{}?tab={}",
        strand_detail_deep_link_path(realm_id, strand_id),
        card_detail_tab_slug(tab)
    )
}

pub(super) fn share_kanban_strand_link(path: &str) {
    let Ok(encoded) = serde_json::to_string(path) else {
        return;
    };
    let script = format!(
        r#"(async () => {{
    const path = {encoded};
    const url = new URL(path, window.location.href).href;
    if (navigator.share) {{
        try {{
            await navigator.share({{ url }});
            return true;
        }} catch (err) {{
            if (err && err.name === "AbortError") {{
                return false;
            }}
        }}
    }}
    if (navigator.clipboard && window.isSecureContext) {{
        await navigator.clipboard.writeText(url);
        return true;
    }}
    const node = document.createElement("textarea");
    node.value = url;
    node.setAttribute("readonly", "");
    node.style.position = "fixed";
    node.style.left = "-9999px";
    document.body.appendChild(node);
    node.select();
    const copied = document.execCommand("copy");
    document.body.removeChild(node);
    return copied;
}})()"#
    );
    let _ = document::eval(&script);
}

pub(super) fn card_summary_text(summary: &str) -> String {
    summary.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn card_detail_draft_from_card(card: &KanbanCard) -> CardDetailDraft {
    CardDetailDraft {
        title: card.title.clone(),
        description: card.description.clone(),
        description_body: card.description_body.clone(),
        synthesis: card.synthesis.clone(),
        labels: card.labels.clone(),
        assignee: editor_value_for_optional_card_field(&card.assignee),
        due: editor_value_for_optional_card_field(&card.due),
        calendar: card.calendar.clone(),
    }
}

pub(super) fn parse_card_labels(raw: &str) -> Vec<String> {
    let mut labels = Vec::new();
    for label in raw
        .split(',')
        .map(str::trim)
        .filter(|label| !label.is_empty())
    {
        if !labels
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(label))
        {
            labels.push(label.to_owned());
        }
    }
    labels
}

pub(super) fn editor_value_for_optional_card_field(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "—" || trimmed.eq_ignore_ascii_case("unscheduled") {
        String::new()
    } else {
        trimmed.to_owned()
    }
}

pub(super) fn display_optional_card_field(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "—" {
        "—".to_owned()
    } else {
        trimmed.to_owned()
    }
}
