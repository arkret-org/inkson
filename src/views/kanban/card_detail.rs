use super::model::*;
use super::{
    CardAuthorDisplayContext, calendar_event_fields_from_draft, card_author_display_label,
    dispatch_card_detail_update, json_path_string,
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
    let tab = card_detail_tab_slug(CardDetailContentTab::default()).to_owned();
    if board_id.is_empty() {
        Route::KanbanTask {
            realm_id,
            task_id,
            tab,
        }
    } else {
        Route::KanbanBoardTask {
            realm_id,
            board_id: board_id.to_owned(),
            task_id,
            tab,
        }
    }
}

pub(super) fn card_matches_strand_id(card: &KanbanCard, strand_id: &str) -> bool {
    let strand_id = strand_id.trim();
    !strand_id.is_empty() && (card.id == strand_id || card.primary_strand_id == strand_id)
}

pub(super) fn card_detail_write_ready(card: &KanbanCard) -> bool {
    arkret_sdk::StrandId::new(card.id.clone()).is_ok()
        && card.state == CardState::Synced
        && card.authoring_basis.is_some()
}

/// Opening a local draft does not submit a write. The save action separately
/// requires the complete, accepted current value.
pub(super) fn card_detail_edit_ready(card: &KanbanCard) -> bool {
    arkret_sdk::StrandId::new(card.id.clone()).is_ok()
}

pub(super) fn card_detail_editor_basis(card: &KanbanCard) -> KanbanCard {
    let mut card = card.clone();
    if !card_detail_write_ready(&card) {
        // An editor opened during a pending write/refresh has not captured an
        // accepted basis. Let reconciliation install the next complete value
        // without replacing the user's independent draft signals.
        card.authoring_basis = None;
    }
    card
}

pub(super) fn prepare_selected_card_for_edit(selected: Cage<Option<KanbanCard>>) {
    let current = selected.get_untracked().clone();
    if let Some(current) = current {
        let next = card_detail_editor_basis(&current);
        if next != current {
            selected.revise(|value| {
                let next = Some(next);
                *value = next;
            });
        }
    }
}

/// Replace only this holder's draft route once its exact accepted card has
/// installed a complete current basis. A canonical link never follows aliases.
pub(super) fn card_task_route_after_acceptance(
    route: &Route,
    card: &KanbanCard,
    raw_operations: &[RawOperationRecord],
) -> Option<Route> {
    let routed_id = route_card_strand_id(route)?;
    if arkret_sdk::StrandId::new(routed_id.clone()).is_ok() || !card_detail_write_ready(card) {
        return None;
    }
    let aliases = event_derived_target_aliases(raw_operations);
    if resolve_event_derived_target_alias(&aliases, &routed_id) != card.id {
        return None;
    }
    match route {
        Route::KanbanTask { realm_id, tab, .. } => Some(Route::KanbanTask {
            realm_id: realm_id.clone(),
            task_id: card.id.clone(),
            tab: tab.clone(),
        }),
        Route::KanbanBoardTask {
            realm_id,
            board_id,
            tab,
            ..
        } => Some(Route::KanbanBoardTask {
            realm_id: realm_id.clone(),
            board_id: board_id.clone(),
            task_id: card.id.clone(),
            tab: tab.clone(),
        }),
        _ => None,
    }
}

pub(super) fn card_discussion_target_ready(card: &KanbanCard) -> bool {
    // A frozen create already has an Event-derived id before the Station
    // accepts it. Discussion and Sidecar context need the accepted current,
    // rather than that locally computed identity.
    card_detail_write_ready(card)
        && arkret_sdk::StrandId::new(card.primary_strand_id.clone()).is_ok()
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
    card_edit_title: Cage<String>,
    card_edit_description: Cage<String>,
    card_edit_body: Cage<String>,
    card_edit_synthesis: Cage<String>,
    card_edit_synthesis_target_id: Cage<Option<String>>,
    card_edit_labels: Cage<String>,
    card_edit_assignee: Cage<String>,
    card_edit_due: Cage<String>,
    editing_card_detail: Cage<bool>,
    card_detail_actions_open: Cage<bool>,
    card_synthesis_history_open_id: Cage<Option<String>>,
    card_synthesis_selected_revision_id: Cage<Option<String>>,
    card_detail_edit_status: Cage<String>,
) {
    let draft = card_detail_draft_from_card(current);
    card_edit_title.revise(|value| {
        let next = draft.title;
        *value = next;
    });
    card_edit_description.revise(|value| {
        let next = draft.description;
        *value = next;
    });
    card_edit_body.revise(|value| {
        let next = draft.description_body;
        *value = next;
    });
    card_edit_synthesis.revise(|value| {
        let next = draft.synthesis;
        *value = next;
    });
    card_edit_synthesis_target_id.revise(|value| {
        let next = None;
        *value = next;
    });
    card_edit_labels.revise(|value| {
        let next = draft.labels.join(", ");
        *value = next;
    });
    card_edit_assignee.revise(|value| {
        let next = draft.assignee;
        *value = next;
    });
    card_edit_due.revise(|value| {
        let next = draft.due;
        *value = next;
    });
    editing_card_detail.revise(|value| {
        let next = false;
        *value = next;
    });
    card_detail_actions_open.revise(|value| {
        let next = false;
        *value = next;
    });
    card_synthesis_history_open_id.revise(|value| {
        let next = None;
        *value = next;
    });
    card_synthesis_selected_revision_id.revise(|value| {
        let next = None;
        *value = next;
    });
    card_detail_edit_status.revise(|value| {
        let next = String::new();
        *value = next;
    });
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn save_card_detail_edit(
    app: Rc<InksonContext>,
    base_url: String,
    token: Cage<String>,
    realm_id: String,
    actor_id: String,
    device_id: String,
    current: KanbanCard,
    synthesis_entries: Vec<CardSynthesisTrackEntry>,
    // R4: three-state security signal (see `kanban_plaintext_block_reason`).
    scope_security_encrypted: Option<bool>,
    sidecar_track_write: Option<SidecarTrackWriteContext>,
    card_edit_scope: Cage<CardEditScope>,
    card_edit_title: Cage<String>,
    card_edit_description: Cage<String>,
    card_edit_body: Cage<String>,
    card_edit_synthesis: Cage<String>,
    card_edit_synthesis_target_id: Cage<Option<String>>,
    card_edit_labels: Cage<String>,
    card_edit_assignee: Cage<String>,
    card_edit_due: Cage<String>,
    editing_card_detail: Cage<bool>,
    card_detail_actions_open: Cage<bool>,
    card_detail_edit_status: Cage<String>,
    selected_card: Cage<Option<KanbanCard>>,
    state_store: SharedStateStore,
    board_status: Cage<String>,
) {
    let Some(active_account) = app.active_account.get().clone() else {
        card_detail_edit_status.revise(|value| {
            let next = "Active account is unavailable".to_owned();
            *value = next;
        });
        return;
    };
    let authority = active_account.authority;
    let account_device_id = active_account.device_id;
    card_detail_edit_status.revise(|value| {
        let next = "Saving...".to_owned();
        *value = next;
    });
    let edit_scope = card_edit_scope.get();
    if sidecar_track_write.is_some() && edit_scope != CardEditScope::Synthesis {
        card_detail_edit_status.revise(|value| {
            let next =
                "Private Sidecar editing is available only on the Synthesis track".to_owned();
            *value = next;
        });
        return;
    }
    let synthesis_target_id = card_edit_synthesis_target_id.get();
    let (draft, synthesis_revision) = card_detail_draft_for_edit_scope(
        &current,
        edit_scope,
        &synthesis_entries,
        synthesis_target_id.as_deref(),
        &card_edit_title.get(),
        &card_edit_description.get(),
        &card_edit_body.get(),
        &card_edit_synthesis.get(),
        &card_edit_labels.get(),
        &card_edit_assignee.get(),
        &card_edit_due.get(),
    );
    let needs_encryption =
        match super::card_patch::card_detail_patch_needs_encryption(&current, &draft) {
            Ok(value) => value,
            Err(error) => {
                card_detail_edit_status.revise(|value| {
                    let next = error;
                    *value = next;
                });
                return;
            }
        };
    let mut current = current;
    let mut scope_security_encrypted = scope_security_encrypted;
    if needs_encryption && sidecar_track_write.is_none() {
        // Re-read the holder's durable choice: a complete pre-Genesis cut is
        // still protocol plaintext, but must not publish this private draft.
        let has_creator_intent = async {
            let api = crate::transport::auth::authed_api_ready(&base_url, token.get()).await?;
            let scope = arkret_sdk::ScopeRef::Realm {
                realm_id: arkret_sdk::RealmId::new(realm_id.clone())?,
            };
            Ok::<_, anyhow::Error>(
                api.event_submitter()?
                    .creator_bootstrap_intent(&scope)
                    .await?
                    .is_some(),
            )
        }
        .await;
        match has_creator_intent {
            Ok(true) => {
                current.security_encrypted = Some(true);
                scope_security_encrypted = Some(true);
            }
            Ok(false) => {}
            Err(error) => {
                card_detail_edit_status.revise(|value| {
                    let next =
                        format!("encryption_transition_pending: read creator intent: {error}");
                    *value = next;
                });
                return;
            }
        }
    }
    let encrypted_realm_write = needs_encryption
        && sidecar_track_write.is_none()
        && current
            .security_encrypted
            .unwrap_or_else(|| scope_security_encrypted.unwrap_or(true));
    if encrypted_realm_write
        && !state_store.read(|store| encrypted_realm_write_mls_ready(store, &realm_id, &authority))
    {
        let session_credential = token.get();
        card_detail_edit_status.revise(|value| {
            let next = "Restoring encrypted Realm state before saving...".to_owned();
            *value = next;
        });
        {
            let task_context = app.clone();
            spawn_write(task_context, async move {
                match recover_mls_checkpoint_for_encrypted_write(
                    app.clone(),
                    &base_url,
                    &session_credential,
                    &realm_id,
                    &actor_id,
                    &authority,
                    &account_device_id,
                    state_store.clone(),
                )
                .await
                {
                    Ok(()) => {
                        if dispatch_card_detail_update(
                            app.clone(),
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
                            state_store.clone(),
                            board_status,
                        )
                        .await
                        {
                            card_detail_edit_status.revise(|value| {
                                let next = String::new();
                                *value = next;
                            });
                            editing_card_detail.revise(|value| {
                                let next = false;
                                *value = next;
                            });
                            card_detail_actions_open.revise(|value| {
                                let next = false;
                                *value = next;
                            });
                        } else {
                            let status = board_status.get();
                            card_detail_edit_status.revise(|value| {
                                let next = if status.trim().is_empty() {
                                    "Unable to save changes.".to_owned()
                                } else {
                                    status
                                };
                                *value = next;
                            });
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            realm = %realm_id,
                            %error,
                            "encrypted Kanban write readiness recovery failed"
                        );
                        board_status.revise(|value| {
                            let next = error.clone();
                            *value = next;
                        });
                        card_detail_edit_status.revise(|value| {
                            let next = error;
                            *value = next;
                        });
                    }
                }
            });
        };
        return;
    }

    if dispatch_card_detail_update(
        app.clone(),
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
        state_store.clone(),
        board_status,
    )
    .await
    {
        card_detail_edit_status.revise(|value| {
            let next = String::new();
            *value = next;
        });
        editing_card_detail.revise(|value| {
            let next = false;
            *value = next;
        });
        card_detail_actions_open.revise(|value| {
            let next = false;
            *value = next;
        });
    } else {
        let status = board_status.get();
        card_detail_edit_status.revise(|value| {
            let next = if status.trim().is_empty() {
                "Unable to save changes.".to_owned()
            } else {
                status
            };
            *value = next;
        });
    }
}

/// Make a Realm-scoped encrypted write independent of the timing of the
/// background MLS effects. A Save click is itself a concrete readiness demand:
/// fetch a pending Welcome, restore a decryptable account history backup, or
/// finish creator genesis before retrying the exact draft the user submitted.
async fn recover_mls_checkpoint_for_encrypted_write(
    app: Rc<InksonContext>,
    base_url: &str,
    session_credential: &str,
    realm_id: &str,
    actor_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    state_store: SharedStateStore,
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
    if state_store.read(|store| encrypted_realm_write_mls_ready(store, realm_id, authority)) {
        return Ok(());
    }

    let mut failures = Vec::new();
    let store_handle = state_store.handle();
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
            app.clone(),
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
    if state_store.read(|store| encrypted_realm_write_mls_ready(store, realm_id, authority)) {
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
    if state_store.read(|store| encrypted_realm_write_mls_ready(store, realm_id, authority)) {
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
    let Ok(realm_id) = arkret_sdk::RealmId::new(realm_id.to_owned()) else {
        return false;
    };
    let scope = arkret_sdk::ScopeRef::Realm { realm_id };
    if state_store.current_mls_group_for_scope(&scope).is_none() {
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
    app: Rc<InksonContext>,
    base_url: String,
    token: Cage<String>,
    realm_id: String,
    actor_id: String,
    device_id: String,
    current: KanbanCard,
    due_value: String,
    scope_security_encrypted: Option<bool>,
    due_picker_open: Cage<bool>,
    due_edit_status: Cage<String>,
    selected_card: Cage<Option<KanbanCard>>,
    state_store: SharedStateStore,
    board_status: Cage<String>,
) -> bool {
    let mut draft = card_detail_draft_from_card(&current);
    draft.due = due_value.trim().to_owned();
    due_edit_status.revise(|value| {
        let next = "Saving...".to_owned();
        *value = next;
    });
    if dispatch_card_detail_update(
        app.clone(),
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
        state_store.clone(),
        board_status,
    )
    .await
    {
        due_edit_status.revise(|value| {
            let next = String::new();
            *value = next;
        });
        due_picker_open.revise(|value| {
            let next = false;
            *value = next;
        });
        true
    } else {
        let status = board_status.get();
        due_edit_status.revise(|value| {
            let next = if status.trim().is_empty() {
                "Unable to save due date.".to_owned()
            } else {
                status
            };
            *value = next;
        });
        false
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn save_card_calendar_edit(
    app: Rc<InksonContext>,
    base_url: String,
    token: Cage<String>,
    realm_id: String,
    actor_id: String,
    device_id: String,
    current: KanbanCard,
    calendar: CalendarCardFields,
    scope_security_encrypted: Option<bool>,
    editing_card_detail: Cage<bool>,
    card_detail_actions_open: Cage<bool>,
    card_detail_edit_status: Cage<String>,
    selected_card: Cage<Option<KanbanCard>>,
    state_store: SharedStateStore,
    board_status: Cage<String>,
) -> bool {
    let mut draft = card_detail_draft_from_card(&current);
    draft.calendar = calendar;
    card_detail_edit_status.revise(|value| {
        let next = "Saving calendar...".to_owned();
        *value = next;
    });
    if dispatch_card_detail_update(
        app.clone(),
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
        state_store.clone(),
        board_status,
    )
    .await
    {
        card_detail_edit_status.revise(|value| {
            let next = String::new();
            *value = next;
        });
        editing_card_detail.revise(|value| {
            let next = false;
            *value = next;
        });
        card_detail_actions_open.revise(|value| {
            let next = false;
            *value = next;
        });
        true
    } else {
        let status = board_status.get();
        card_detail_edit_status.revise(|value| {
            let next = if status.trim().is_empty() {
                "Unable to save calendar.".to_owned()
            } else {
                status
            };
            *value = next;
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

/// The local raw-operation record of an RSVP the Station accepted.
#[derive(serde::Serialize)]
struct SyncedCalendarRsvpRecord<'a> {
    kind: &'a str,
    operation_id: &'a str,
    event_id: &'a str,
    local_operation_idempotency_alias: &'a str,
    actor_id: &'a str,
    created_at: String,
    write_state: &'static str,
    body: arkret_sdk::RsvpSetPayload,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch_calendar_rsvp(
    app: Rc<InksonContext>,
    base_url: String,
    token: Cage<String>,
    realm_id: String,
    actor_id: String,
    card: KanbanCard,
    status: &'static str,
    occurrence: String,
    state_store: SharedStateStore,
    board_status: Cage<String>,
) {
    if card.state != CardState::Synced {
        board_status.revise(|value| {
            let next = "cannot build RSVP: resolve the current Card first".to_owned();
            *value = next;
        });
        return;
    }
    // calendar-event.md section 8.5: an authoring client that cannot read the
    // deterministic schedule winner MUST refuse to construct the RSVP. The
    // winner arrives on the Strand projection; there is no Event-log traversal
    // to fall back on, because a producer Event carries no causal edges and the
    // client keeps no Realm-global order to walk.
    let schedule_basis_refs = card.calendar_schedule_basis_refs();
    if schedule_basis_refs.len() != 1 {
        board_status.revise(|value| {
            let next =
                "cannot build RSVP: calendar_schedule_unavailable - no readable schedule winner"
                    .to_owned();
            *value = next;
        });
        return;
    }
    let submit_token = token.get();
    let strand_id = card.primary_strand_id.clone();
    let calendar = card.calendar.clone();
    let build_realm_id = realm_id.clone();
    let build_actor_id = actor_id.clone();
    {
        let task_context = app.clone();
        spawn_write(task_context, async move {
            let built = (|| {
                let [schedule_basis_event] = schedule_basis_refs.as_slice() else {
                    anyhow::bail!(
                        "calendar_schedule_unavailable - expected exactly one schedule Event"
                    );
                };
                let fields =
                    calendar_event_fields_from_draft(&calendar).map_err(anyhow::Error::msg)?;
                let actor = crate::mls_api_helpers::local_account_actor_id(&build_actor_id)?;
                let active = crate::secure_key_store::active_device_seed_scope()
                    .ok_or_else(|| anyhow::anyhow!("active RSVP device is unavailable"))?;
                let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                state_store.write(|store| {
                    crate::calendar::build_encrypted_calendar_rsvp_event(
                        store,
                        secure_store.as_ref(),
                        &build_realm_id,
                        &actor,
                        &active.device_id,
                        &strand_id,
                        status,
                        (!occurrence.trim().is_empty()
                            && !calendar.recurrence_frequency.trim().is_empty())
                        .then_some(occurrence.trim()),
                        &fields,
                        schedule_basis_event.clone(),
                    )
                })
            })();
            match built {
                Ok(event) => {
                    let operation_id = event.local_operation_id().to_string();
                    let kind = event.kind().as_str().to_owned();
                    let body = match event.typed_payload::<arkret_wire::event_spec::RsvpSet>() {
                        Ok(body) => body,
                        Err(err) => {
                            board_status.revise(|value| {
                                let next = format!("cannot queue RSVP: {err:#}");
                                *value = next;
                            });
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
                            board_status.revise(|value| {
                                let next = format!("cannot queue RSVP: {err}");
                                *value = next;
                            });
                            return;
                        }
                    };
                    state_store.write(|store| {
                        store.enqueue_local_projection_command(
                            operation_id.clone(),
                            Some(realm_id.clone()),
                            record,
                        )
                    });
                    board_status.revise(|value| {
                        let next = format!("submitting RSVP {}", short_protocol_id(&operation_id));
                        *value = next;
                    });
                    let submitted = with_authed_api(&base_url, submit_token, |api| async move {
                        api.event_submitter()?.submit_sdk_event(&event).await
                    })
                    .await;
                    let Ok(response) = submitted else {
                        board_status.revise(|value| {
                            let next = format!("RSVP failed: {submitted:#?}");
                            *value = next;
                        });
                        return;
                    };
                    let accepted_event_id = response.event_id.clone();
                    let record = match serde_json::to_value(SyncedCalendarRsvpRecord {
                        kind: &kind,
                        operation_id: &accepted_event_id,
                        event_id: &response.event_id,
                        local_operation_idempotency_alias: &operation_id,
                        actor_id: &actor_id,
                        created_at: arkret_sdk::canonical::format_timestamp_canonical(
                            crate::clock::now_utc(),
                        ),
                        write_state: "synced",
                        body,
                    }) {
                        Ok(record) => record,
                        Err(err) => {
                            board_status.revise(|value| {
                                let next = format!("cannot record RSVP: {err}");
                                *value = next;
                            });
                            return;
                        }
                    };
                    state_store.write(|store| {
                        store.upsert_raw_operation(
                            accepted_event_id.clone(),
                            Some(realm_id),
                            record,
                        )
                    });
                    board_status.revise(|value| {
                        let next = format!(
                            "{} accepted as {}",
                            kind,
                            short_protocol_id(&response.event_id)
                        );
                        *value = next;
                    });
                }
                Err(err) => {
                    board_status.revise(|value| {
                        let next = format!("cannot build RSVP: {err:#?}");
                        *value = next;
                    });
                }
            }
        });
    };
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

pub(super) fn card_detail_tab_from_slug(value: &str) -> Option<CardDetailContentTab> {
    match value.trim().to_ascii_lowercase().as_str() {
        "description" => Some(CardDetailContentTab::Description),
        "synthesis" => Some(CardDetailContentTab::Synthesis),
        "discussion" => Some(CardDetailContentTab::Discussion),
        _ => None,
    }
}

pub(super) fn card_detail_tab_from_route(route: &Route) -> CardDetailContentTab {
    match route {
        Route::KanbanTask { tab, .. } | Route::KanbanBoardTask { tab, .. } => {
            card_detail_tab_from_slug(tab).unwrap_or_default()
        }
        _ => CardDetailContentTab::default(),
    }
}

pub(super) fn card_detail_tab_from_current_route(app: &InksonContext) -> CardDetailContentTab {
    card_detail_tab_from_route(&app.route.get())
}

pub(super) fn card_task_route_with_tab(route: &Route, tab: CardDetailContentTab) -> Option<Route> {
    let mut route = route.clone();
    match &mut route {
        Route::KanbanTask {
            tab: routed_tab, ..
        }
        | Route::KanbanBoardTask {
            tab: routed_tab, ..
        } => {
            *routed_tab = card_detail_tab_slug(tab).to_owned();
        }
        _ => return None,
    }
    Some(route)
}

pub(super) fn replace_card_detail_tab_query(app: Rc<InksonContext>, tab: CardDetailContentTab) {
    if let Some(route) = card_task_route_with_tab(&app.route.get_untracked(), tab) {
        app.replace_route(route);
    }
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

pub(super) fn share_kanban_strand_link(app: Rc<InksonContext>, path: &str) {
    let path = path.to_owned();
    let root = app.clone();
    spawn_write(root, async move {
        #[cfg(target_arch = "wasm32")]
        let base = web_sys::window()
            .and_then(|window| window.location().href().ok())
            .unwrap_or_else(|| app.base_url.get_untracked());
        #[cfg(not(target_arch = "wasm32"))]
        let base = app.base_url.get_untracked();
        let url = url::Url::parse(&base)
            .and_then(|base| base.join(&path))
            .map(|url| url.to_string())
            .unwrap_or(path);
        #[cfg(target_arch = "wasm32")]
        {
            use wasm_bindgen::JsCast;
            if let Some(window) = web_sys::window() {
                let navigator = window.navigator();
                if let Ok(share) = js_sys::Reflect::get(
                    navigator.as_ref(),
                    &wasm_bindgen::JsValue::from_str("share"),
                ) && let Ok(share) = share.dyn_into::<js_sys::Function>()
                {
                    let data = js_sys::Object::new();
                    let _ = js_sys::Reflect::set(
                        &data,
                        &wasm_bindgen::JsValue::from_str("url"),
                        &wasm_bindgen::JsValue::from_str(&url),
                    );
                    match share.call1(navigator.as_ref(), &data) {
                        Ok(result) => {
                            if let Ok(promise) = result.dyn_into::<js_sys::Promise>() {
                                let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            }
        }
        if let Err(error) = crate::components::platform_io::copy_text(&url).await {
            tracing::warn!(%error,"card link copy failed");
        }
    });
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
