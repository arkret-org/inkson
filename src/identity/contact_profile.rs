//! Authorized co-member Actor Profile reads behind the Contact identity
//! surfaces.
//!
//! The protocol orchestration — request shape, per-row validation, and the
//! fresh / stale / unavailable verdict — belongs to
//! [`garth::ActorProfileDirectory`]. This module is only the host adapter: one
//! process-wide cache, a session reset hook, and a spawn helper that feeds the
//! authenticated SDK client into it.
//!
//! The authorization basis is a shared Collaboration Realm, so a Contact row
//! can only resolve its peer once the pair has a Direct Conversation Realm. A
//! Contact with no shared Realm yet has no reachable profile, which is the same
//! `unknown` a UI must not read as "this peer has not renamed".

use std::sync::{LazyLock, RwLock};

use arkret_models_collaboration::actor_profile_resolution::ConfirmedDisplayNameState;

use crate::account_data::ContactRemark;

static DIRECTORY: LazyLock<RwLock<garth::ActorProfileDirectory>> =
    LazyLock::new(|| RwLock::new(garth::ActorProfileDirectory::new()));

/// Forget every cached row on logout or account switch.
///
/// The rows were authorized by one holder's memberships, so they must not
/// survive into another session.
pub(crate) fn reset_session_cache() {
    *DIRECTORY
        .write()
        .unwrap_or_else(|poison| poison.into_inner()) = garth::ActorProfileDirectory::new();
}

/// Drop the rows a Realm membership authorized, after leaving or suspension.
pub(crate) fn forget_realm(realm_id: &arkret_sdk::RealmId) {
    DIRECTORY
        .write()
        .unwrap_or_else(|poison| poison.into_inner())
        .forget_realm(realm_id);
}

/// Current verified profile display for a peer, fresh or stale.
///
/// This is the live secondary label a row renders when the holder has no
/// petname; it is not the confirmation baseline.
pub(crate) fn current_display_name(
    realm_id: &arkret_sdk::RealmId,
    actor_id: &arkret_sdk::ActorId,
) -> Option<String> {
    DIRECTORY
        .read()
        .unwrap_or_else(|poison| poison.into_inner())
        .view(realm_id, actor_id, chrono::Utc::now())
        .displayable()
        .map(|profile| profile.display_name.clone())
}

/// Compare the holder's confirmation baseline against current evidence.
pub(crate) fn confirmed_display_name_state(
    realm_id: &arkret_sdk::RealmId,
    actor_id: &arkret_sdk::ActorId,
    remark: Option<&ContactRemark>,
) -> ConfirmedDisplayNameState {
    DIRECTORY
        .read()
        .unwrap_or_else(|poison| poison.into_inner())
        .confirmed_display_name_state(realm_id, actor_id, remark, chrono::Utc::now())
}

/// Resolve the actors in `realm_id` that are due for a read and install every
/// outcome, including the failures.
///
/// The freshness decision and the row validation both stay in garth; the reason
/// the round trip is spelled out here rather than calling
/// [`garth::ActorProfileDirectory::refresh`] is that the authenticated client
/// only exists inside `with_authed_sdk_client`, and holding the cache lock
/// across that await would serialize every render behind one network call.
pub(crate) async fn refresh(
    base_url: &str,
    api_token: String,
    realm_id: arkret_sdk::RealmId,
    actor_ids: Vec<arkret_sdk::ActorId>,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now();
    let pending = DIRECTORY
        .read()
        .unwrap_or_else(|poison| poison.into_inner())
        .pending_refresh(&realm_id, &actor_ids, now);
    if pending.is_empty() {
        return Ok(());
    }
    let outcome = crate::transport::auth::with_authed_sdk_client(base_url, api_token, {
        let realm_id = realm_id.clone();
        let pending = pending.clone();
        move |http| async move {
            let request = arkret_sdk::ActorProfileResolveRequest::new(realm_id, pending);
            http.actor_profile_resolve(&request)
                .await
                .map_err(anyhow::Error::from)
        }
    })
    .await
    .map_err(|error| anyhow::anyhow!("{}", error.display()))?;
    DIRECTORY
        .write()
        .unwrap_or_else(|poison| poison.into_inner())
        .record(&realm_id, &pending, outcome, chrono::Utc::now());
    Ok(())
}

/// The display name a fresh, validated row carries, if any.
///
/// Contact accept uses this as the confirmation baseline: a value here means the
/// accept surface actually held verified profile evidence, which is the only
/// condition under which the baseline may be initialized at all.
pub(crate) fn current_verified_display_name(
    realm_id: &arkret_sdk::RealmId,
    actor_id: &arkret_sdk::ActorId,
) -> Option<String> {
    DIRECTORY
        .read()
        .unwrap_or_else(|poison| poison.into_inner())
        .view(realm_id, actor_id, chrono::Utc::now())
        .current_evidence()
        .map(|evidence| evidence.actor_profile.display_name.clone())
}
