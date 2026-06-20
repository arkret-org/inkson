use crate::local_state::LocalStateStore;
use crate::secure_key_store::SecureKeyStore;

#[derive(Clone, Debug)]
pub struct CircleScopeRotateDraft {
    pub events: Vec<cokret_sdk::Event>,
    pub post_commit_snapshot: crate::mls::persistence::MlsSnapshotEnvelope,
    pub removed_leaves: Vec<u32>,
    pub removed_principals: Vec<String>,
}

pub fn build_circle_remove_scope_rotate_draft(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: &str,
    actor_id: &str,
    device_id: &str,
    target_principal_id: &str,
) -> Result<CircleScopeRotateDraft, String> {
    let circle = circle_id.trim();
    if circle.is_empty() {
        return Err("circle_id is required for Circle MLS scope rotate".to_owned());
    }
    let (remove, post_commit_snapshot) =
        crate::mls::runtime::build_mls_remove_commit_for_effective_scope(
            state_store,
            secure_store,
            realm_id,
            Some(circle),
            actor_id,
            device_id,
            target_principal_id,
        )
        .map_err(|err| err.user_message())?;
    let commit_event =
        crate::views::kanban::kanban_mls_commit_event_from_store_for_effective_scope(
            state_store,
            realm_id,
            Some(circle),
            actor_id,
            &remove.commit,
        )?;
    Ok(CircleScopeRotateDraft {
        events: vec![commit_event],
        post_commit_snapshot,
        removed_leaves: remove.removed_leaves,
        removed_principals: remove
            .removed_principals
            .into_iter()
            .map(|did| did.to_string())
            .collect(),
    })
}

pub async fn submit_circle_scope_rotate_draft(
    api: &crate::api::CokretApi,
    state_store: &mut LocalStateStore,
    realm_id: &str,
    circle_id: &str,
    draft: CircleScopeRotateDraft,
) -> anyhow::Result<cokret_sdk::CircleScopeRotateOutcome> {
    let outcome = api
        .submit_circle_scope_rotate_events(circle_id, &draft.events, None)
        .await?;
    if !outcome.accepted.is_empty() || !outcome.duplicate.is_empty() {
        state_store.save_mls_snapshot_for_effective_scope(
            realm_id.to_owned(),
            Some(circle_id),
            draft.post_commit_snapshot,
        );
    }
    Ok(outcome)
}
