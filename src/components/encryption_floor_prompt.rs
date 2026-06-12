use std::collections::BTreeMap;

use dioxus::prelude::*;
use dioxus_router::hooks::use_navigator;
use serde_json::Value;

use crate::local_state::LocalStateStore;
use crate::realm_tree::string_field;
use crate::routes::Route;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::dialog::Dialog;

#[component]
pub fn EncryptionFloorPrompt(
    token: Signal<String>,
    account_did: Signal<String>,
    state_store: Signal<LocalStateStore>,
    sync_bootstrap_complete: Signal<bool>,
    needs_mls_unlock: Signal<bool>,
    needs_mls_backup: Signal<bool>,
) -> Element {
    let mut dismissed = use_signal(|| false);
    let mut status = use_signal(String::new);
    let navigator = use_navigator();

    let session = token();
    let actor = account_did();
    if dismissed()
        || !sync_bootstrap_complete()
        || session.trim().is_empty()
        || actor.trim().is_empty()
        || needs_mls_unlock()
        || needs_mls_backup()
        || !account_needs_recommended_encryption_prompt(&state_store.read(), &actor)
    {
        return rsx! {};
    }

    let has_local_account_secret = {
        let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
        matches!(
            crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), &actor),
            Ok(Some(_))
        )
    };

    let on_enable = move |_| {
        dismissed.set(true);
        if has_local_account_secret {
            needs_mls_backup.set(true);
        }
        let _ = navigator.push(Route::SettingsRecovery);
    };

    rsx! {
        Dialog {
            open: true,
            on_open_change: move |open: bool| {
                if !open {
                    dismissed.set(true);
                }
            },
            "data-testid": "recommended-encryption-floor-modal",
            "aria-labelledby": "recommended-encryption-floor-title",
            "aria-label": "Recommended encryption is not enabled",
            div {
                class: "modal event mls-recovery-modal",
                "data-testid": "recommended-encryption-floor-banner",
                div { class: "modal-head event-head",
                    h3 { id: "recommended-encryption-floor-title", "Use recommended encryption" }
                    span { class: "muted", "PCR / Realm floor" }
                }
                div { class: "modal-body mls-recovery-modal-body",
                    div { class: "muted",
                        "The current account has no evidence of the recommended metadata and content encryption floor. Principal Control Realm and private collaboration state should use MLS with metadata_encryption_floor=e2ee_required and content_encryption_floor=e2ee_required."
                    }
                    div { class: "muted",
                        "Choosing the recommended mode opens Recovery Key setup first. If encrypted material already exists on this device, the key-backup prompt will appear immediately; otherwise the app will ask again when the first encrypted Realm creates MLS material."
                    }
                    if !status().is_empty() {
                        div { class: "muted", "data-testid": "recommended-encryption-floor-status", "{status}" }
                    }
                }
                div { class: "modal-foot mls-backup-row",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "recommended-encryption-floor-enable",
                        onclick: on_enable,
                        "Use recommended encryption"
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "recommended-encryption-floor-dismiss",
                        onclick: move |_| {
                            dismissed.set(true);
                            status.set(String::new());
                        },
                        "Not now"
                    }
                }
            }
        }
    }
}

pub(crate) fn account_needs_recommended_encryption_prompt(
    state_store: &LocalStateStore,
    account_did: &str,
) -> bool {
    account_needs_recommended_encryption_prompt_for_projections(
        account_did,
        &state_store.load().realm_tree_projections,
    )
}

pub(crate) fn account_needs_recommended_encryption_prompt_for_projections(
    account_did: &str,
    projections: &BTreeMap<String, Value>,
) -> bool {
    let actor = account_did.trim();
    if actor.is_empty() {
        return false;
    }

    let pcr_realm_id = cokret_sdk::Did::new(actor.to_owned())
        .ok()
        .map(|did| cokret_sdk::auth::principal_control_realm_id(&did));
    if let Some(pcr) = pcr_realm_id
        .as_deref()
        .and_then(|realm_id| projections.get(realm_id))
    {
        return !projection_has_recommended_encryption_floor(pcr);
    }

    let mut saw_realm = false;
    let mut saw_recommended = false;
    let mut saw_low_floor_encrypted = false;
    for (id, body) in projections {
        if !projection_is_realm(id, body) {
            continue;
        }
        saw_realm = true;
        if projection_has_recommended_encryption_floor(body) {
            saw_recommended = true;
        } else if crate::security_state::realm_projection_is_encrypted(body) {
            saw_low_floor_encrypted = true;
        }
    }

    if saw_low_floor_encrypted {
        return true;
    }
    if saw_recommended {
        return false;
    }
    !saw_realm
        || projections
            .values()
            .any(|body| !projection_has_recommended_encryption_floor(body))
}

pub(crate) fn projection_has_recommended_encryption_floor(value: &Value) -> bool {
    let profile = projection_string_field(value, &["encryption_profile"]);
    let content_floor = projection_string_field(value, &["content_encryption_floor"]);
    let metadata_floor = projection_string_field(value, &["metadata_encryption_floor"]);

    profile
        .as_deref()
        .is_some_and(crate::api::encryption_profile_uses_recommended_floor)
        && content_floor.as_deref() == Some(crate::api::RECOMMENDED_REALM_ENCRYPTION_FLOOR)
        && metadata_floor.as_deref() == Some(crate::api::RECOMMENDED_REALM_ENCRYPTION_FLOOR)
}

fn projection_is_realm(id: &str, body: &Value) -> bool {
    id.starts_with("ck:realm:")
        || string_field(body, &["__kind"]).as_deref() == Some("realm")
        || string_field(body, &["schema"]).as_deref() == Some("ck.schema.realm.v1")
}

fn projection_string_field(value: &Value, keys: &[&str]) -> Option<String> {
    [
        value,
        value.get("summary").unwrap_or(&Value::Null),
        value.get("object").unwrap_or(&Value::Null),
        value.get("realm").unwrap_or(&Value::Null),
        value.get("metadata").unwrap_or(&Value::Null),
    ]
    .into_iter()
    .find_map(|container| string_field(container, keys))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn recommended_floor_requires_profile_content_and_metadata() {
        assert!(projection_has_recommended_encryption_floor(&json!({
            "encryption_profile": "mls_rfc9420",
            "content_encryption_floor": "e2ee_required",
            "metadata_encryption_floor": "e2ee_required"
        })));
        assert!(!projection_has_recommended_encryption_floor(&json!({
            "encryption_profile": "mls_rfc9420"
        })));
        assert!(!projection_has_recommended_encryption_floor(&json!({
            "encryption_profile": "none",
            "content_encryption_floor": "e2ee_required",
            "metadata_encryption_floor": "e2ee_required"
        })));
    }

    #[test]
    fn pcr_projection_controls_prompt_when_present() {
        let actor = "did:web:alice.example";
        let pcr_id = cokret_sdk::auth::principal_control_realm_id(
            &cokret_sdk::Did::new(actor.to_owned()).unwrap(),
        );
        let mut projections = BTreeMap::new();
        projections.insert(
            "ck:realm:0196419b-0000-7000-8000-000000000001".to_owned(),
            json!({
                "encryption_profile": "mls_rfc9420",
                "content_encryption_floor": "e2ee_required",
                "metadata_encryption_floor": "e2ee_required"
            }),
        );
        projections.insert(
            pcr_id,
            json!({
                "encryption_profile": "mls_rfc9420"
            }),
        );

        assert!(account_needs_recommended_encryption_prompt_for_projections(
            actor,
            &projections
        ));
    }

    #[test]
    fn recommended_collaboration_realm_suppresses_prompt_without_pcr_projection() {
        let mut projections = BTreeMap::new();
        projections.insert(
            "ck:realm:0196419b-0000-7000-8000-000000000001".to_owned(),
            json!({
                "summary": {
                    "encryption_profile": "mls_rfc9420",
                    "content_encryption_floor": "e2ee_required",
                    "metadata_encryption_floor": "e2ee_required"
                }
            }),
        );

        assert!(
            !account_needs_recommended_encryption_prompt_for_projections(
                "did:web:alice.example",
                &projections
            )
        );
    }
}
