//! Pre-accept preview of a directed Realm invite.
//!
//! The invite card loads the preview on its own, independently of Accept: a
//! loaded, restricted or failed preview never joins the Realm, and only the
//! user's explicit Accept click starts the join. The preview comes from this
//! account's own Station, which verifies the Realm's current governance
//! Station and relays what that Station's preview policy discloses.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use chrono::{DateTime, Utc};
use dioxus::prelude::*;

use crate::transport::invite_join::{InvitePreviewOutcome, invite_preview_cache_key};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};

/// What the invite card shows about the invited Realm before Accept.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum InvitePreviewView {
    Loading,
    Disclosed(arkret_sdk::RealmPublicPreview),
    /// Nothing is disclosed to this account; the card still offers Accept.
    Restricted,
    /// The private delivery credential has not reached this device yet, so
    /// there is no locator set to ask with.
    AwaitingDelivery,
    /// The Station or the governance Station could not answer; retryable.
    Unavailable(String),
}

struct CachedPreview {
    preview: arkret_sdk::RealmPublicPreview,
    fresh_until: DateTime<Utc>,
}

/// Disclosed answers keyed by account and exact join target, kept only while
/// the nonce-bound assertion they were verified under is unexpired.
fn preview_cache() -> &'static Mutex<HashMap<String, CachedPreview>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CachedPreview>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn cached_invite_preview(
    key: &str,
    now: DateTime<Utc>,
) -> Option<arkret_sdk::RealmPublicPreview> {
    let mut cache = preview_cache().lock().ok()?;
    cache.retain(|_, cached| cached.fresh_until > now);
    cache.get(key).map(|cached| cached.preview.clone())
}

pub(crate) fn remember_invite_preview(
    key: String,
    preview: arkret_sdk::RealmPublicPreview,
    fresh_until: DateTime<Utc>,
) {
    if let Ok(mut cache) = preview_cache().lock() {
        cache.insert(
            key,
            CachedPreview {
                preview,
                fresh_until,
            },
        );
    }
}

/// The join target this card previews, or `None` without a usable delivery
/// credential.
fn preview_target(
    realm_id: &str,
    invite_id: &str,
    credential: Option<&crate::state::StoredInviteCredential>,
) -> Option<arkret_sdk::RealmJoinTarget> {
    let credential = credential?;
    Some(arkret_sdk::RealmJoinTarget {
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned()).ok()?,
        invite_id: Some(arkret_sdk::InviteId::new(invite_id.to_owned()).ok()?),
        authority_locator_hints: credential.authority_locator_hints.clone(),
    })
}

async fn load_invite_preview(
    base_url: String,
    session_credential: String,
    authority: arkret_sdk::AccountId,
    realm_id: String,
    invite_id: String,
    credential: Option<crate::state::StoredInviteCredential>,
) -> InvitePreviewView {
    let Some(target) = preview_target(&realm_id, &invite_id, credential.as_ref()) else {
        return InvitePreviewView::AwaitingDelivery;
    };
    let Ok(key) = invite_preview_cache_key(&authority, &target) else {
        return InvitePreviewView::Unavailable("invalid invite target".to_owned());
    };
    if let Some(preview) = cached_invite_preview(&key, crate::clock::now_utc()) {
        return InvitePreviewView::Disclosed(preview);
    }
    let result = crate::transport::auth::with_authed_api(&base_url, session_credential, |api| {
        let realm_id = realm_id.clone();
        let invite_id = invite_id.clone();
        async move {
            let credential =
                credential.ok_or_else(|| anyhow::anyhow!("missing invite credential"))?;
            api.preview_realm_invite(&realm_id, &invite_id, &credential)
                .await
        }
    })
    .await;
    match result {
        Ok(InvitePreviewOutcome::Disclosed {
            preview,
            fresh_until,
        }) => {
            remember_invite_preview(key, preview.clone(), fresh_until);
            InvitePreviewView::Disclosed(preview)
        }
        Ok(InvitePreviewOutcome::Restricted) => InvitePreviewView::Restricted,
        Err(error) => InvitePreviewView::Unavailable(error.display()),
    }
}

fn join_rule_label(rule: arkret_sdk::JoinRule) -> &'static str {
    match rule {
        arkret_sdk::JoinRule::Public => "notifications.invite_preview.join_rule.public",
        arkret_sdk::JoinRule::Invite => "notifications.invite_preview.join_rule.invite",
        arkret_sdk::JoinRule::Knock => "notifications.invite_preview.join_rule.knock",
        arkret_sdk::JoinRule::Restricted => "notifications.invite_preview.join_rule.restricted",
        arkret_sdk::JoinRule::KnockRestricted => {
            "notifications.invite_preview.join_rule.knock_restricted"
        }
        arkret_sdk::JoinRule::Closed => "notifications.invite_preview.join_rule.closed",
    }
}

fn history_access_label(access: arkret_sdk::HistoryAccess) -> &'static str {
    match access {
        arkret_sdk::HistoryAccess::SinceJoin => "notifications.invite_preview.history.since_join",
        arkret_sdk::HistoryAccess::AllHistoryForCurrentMembers => {
            "notifications.invite_preview.history.all_history"
        }
    }
}

#[component]
pub(crate) fn InvitePreview(
    base_url: String,
    token: Signal<String>,
    authority: arkret_sdk::AccountId,
    realm_id: String,
    invite_id: String,
    credential: Option<crate::state::StoredInviteCredential>,
) -> Element {
    let mut attempt = use_signal(|| 0u32);
    let preview = use_resource(move || {
        let _ = attempt();
        load_invite_preview(
            base_url.clone(),
            token(),
            authority.clone(),
            realm_id.clone(),
            invite_id.clone(),
            credential.clone(),
        )
    });
    let view = preview.read().clone().unwrap_or(InvitePreviewView::Loading);
    rsx! {
        div {
            class: "invite-preview muted",
            "data-testid": "invite-preview",
            match view {
                InvitePreviewView::Loading => rsx! {
                    span { "data-testid": "invite-preview-loading",
                        {crate::i18n::tr("notifications.invite_preview.loading")}
                    }
                },
                InvitePreviewView::Disclosed(preview) => rsx! {
                    div { "data-testid": "invite-preview-disclosed",
                        if let Some(name) = preview.display_name.clone() {
                            div { class: "entity-title", "data-testid": "invite-preview-name", "{name}" }
                        }
                        div { "data-testid": "invite-preview-join-rule",
                            {crate::i18n::tr(join_rule_label(preview.join_rule))}
                        }
                        div { "data-testid": "invite-preview-history",
                            {crate::i18n::tr(history_access_label(preview.history_access))}
                        }
                    }
                },
                InvitePreviewView::Restricted => rsx! {
                    span { "data-testid": "invite-preview-restricted",
                        {crate::i18n::tr("notifications.invite_preview.restricted")}
                    }
                },
                InvitePreviewView::AwaitingDelivery => rsx! {
                    span { "data-testid": "invite-preview-awaiting",
                        {crate::i18n::tr("notifications.invite_preview.awaiting_delivery")}
                    }
                },
                InvitePreviewView::Unavailable(reason) => rsx! {
                    span { "data-testid": "invite-preview-unavailable", title: "{reason}",
                        {crate::i18n::tr("notifications.invite_preview.unavailable")}
                    }
                    Button {
                        variant: ButtonVariant::Ghost,
                        size: ButtonSize::Sm,
                        "data-testid": "invite-preview-retry",
                        onclick: move |_| attempt += 1,
                        {crate::i18n::tr("notifications.invite_preview.retry")}
                    }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realm_id() -> arkret_sdk::RealmId {
        arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [0x31; 32],
        ))
    }

    fn invite_id(byte: u8) -> arkret_sdk::InviteId {
        arkret_sdk::InviteId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [byte; 32],
        ))
    }

    fn hint(service: &str) -> arkret_sdk::RealmJoinCandidate {
        serde_json::from_value(serde_json::json!({
            "service_kind": "station",
            "service_id": format!("ak:did_core:web:{service}.example"),
            "source": "invite"
        }))
        .unwrap()
    }

    fn credential(service: &str) -> crate::state::StoredInviteCredential {
        crate::state::StoredInviteCredential {
            realm_id: realm_id(),
            authority_locator_hints: vec![hint(service)],
            expires_at: None,
            received_at: Utc::now(),
        }
    }

    fn account(station: &str) -> arkret_sdk::AccountId {
        arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            arkret_sdk::DidCoreId::new(format!("ak:did_core:web:{station}.example")).unwrap(),
        )
    }

    fn preview() -> arkret_sdk::RealmPublicPreview {
        arkret_sdk::RealmPublicPreview {
            realm_id: realm_id(),
            join_rule: arkret_sdk::JoinRule::Invite,
            history_access: arkret_sdk::HistoryAccess::SinceJoin,
            governance_generation: 0,
            display_name: Some("Preview Realm".to_owned()),
        }
    }

    #[test]
    fn preview_needs_the_delivered_locator_set() {
        let invite = invite_id(0x41);
        assert_eq!(
            preview_target(realm_id().as_str(), invite.as_str(), None),
            None,
            "without the private delivery credential there is nothing to ask with"
        );
        let target = preview_target(
            realm_id().as_str(),
            invite.as_str(),
            Some(&credential("gov")),
        )
        .expect("target from the delivered hints");
        assert_eq!(target.invite_id.as_ref(), Some(&invite));
        assert_eq!(target.authority_locator_hints, vec![hint("gov")]);
    }

    #[test]
    fn cache_key_binds_the_exact_account_and_target() {
        let bob = account("bob-station");
        let target = |invite: u8, service: &str| {
            preview_target(
                realm_id().as_str(),
                invite_id(invite).as_str(),
                Some(&credential(service)),
            )
            .unwrap()
        };
        let key = invite_preview_cache_key(&bob, &target(0x41, "gov")).unwrap();
        assert_eq!(
            key,
            invite_preview_cache_key(&bob, &target(0x41, "gov")).unwrap()
        );
        assert_ne!(
            key,
            invite_preview_cache_key(&account("other-station"), &target(0x41, "gov")).unwrap(),
            "the same principal at another Station is another account"
        );
        assert_ne!(
            key,
            invite_preview_cache_key(&bob, &target(0x42, "gov")).unwrap()
        );
        assert_ne!(
            key,
            invite_preview_cache_key(&bob, &target(0x41, "elsewhere")).unwrap()
        );
    }

    #[test]
    fn cached_preview_lives_only_while_its_assertion_is_fresh() {
        let now = Utc::now();
        let key = format!("test-{}", now.timestamp_nanos_opt().unwrap_or_default());
        remember_invite_preview(key.clone(), preview(), now + chrono::Duration::seconds(30));
        assert_eq!(cached_invite_preview(&key, now), Some(preview()));
        assert_eq!(
            cached_invite_preview(&key, now + chrono::Duration::seconds(30)),
            None
        );
        assert_eq!(
            cached_invite_preview(&key, now),
            None,
            "expired entries are evicted"
        );
    }
}
