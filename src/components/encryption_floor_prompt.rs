use std::collections::BTreeMap;

use dioxus::prelude::*;
use serde_json::Value;

use crate::local_state::LocalStateStore;
use crate::realm_tree::string_field;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::dialog::Dialog;

#[component]
pub fn EncryptionFloorPrompt(
    token: Signal<String>,
    account_did: Signal<String>,
    state_store: Signal<LocalStateStore>,
    sync_bootstrap_complete: Signal<bool>,
    device_authorization_check_complete: Signal<bool>,
    needs_device_authorization: Signal<bool>,
    needs_mls_unlock: Signal<bool>,
    needs_mls_backup: Signal<bool>,
    recovery_key_setup_prompt: Signal<bool>,
) -> Element {
    let mut dismissed = use_signal(|| false);
    let mut status = use_signal(String::new);

    let session = token();
    let actor = account_did();
    if dismissed()
        || !sync_bootstrap_complete()
        || !device_authorization_check_complete()
        || session.trim().is_empty()
        || actor.trim().is_empty()
        || needs_device_authorization()
        || needs_mls_unlock()
        || needs_mls_backup()
        || !account_needs_recommended_encryption_prompt(&state_store.read(), &actor)
    {
        return rsx! {};
    }

    let recovery_key_configured =
        crate::views::recovery::recovery_options_configured(&state_store.read(), &actor);
    let on_enable = move |_| {
        if recovery_key_configured {
            dismissed.set(true);
            status.set(String::new());
        } else {
            dismissed.set(true);
            recovery_key_setup_prompt.set(true);
        }
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
                    if recovery_key_configured {
                        div { class: "muted",
                            "Your 24-word Recovery Key is already configured. For new private Realms, choose MLS with metadata and content floors set to e2ee_required; existing low-floor Realms need an explicit policy ratchet where the Realm supports it."
                        }
                    } else {
                        div { class: "muted",
                            "Choosing the recommended mode opens the 24-word Recovery Key setup prompt first. If encrypted material already exists on this device, the prompt will back it up immediately; otherwise the first encrypted Realm will use this Recovery Key when MLS material is created."
                        }
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
                        if recovery_key_configured {
                            "Use recommended encryption for new Realms"
                        } else {
                            "Set up 24-word Recovery Key"
                        }
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
    if projections.is_empty() {
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

    let mut saw_recommended = false;
    let mut saw_low_floor_encrypted = false;
    for (id, body) in projections {
        if !projection_is_realm(id, body) {
            continue;
        }
        if projection_has_recommended_encryption_floor(body) {
            saw_recommended = true;
        } else if projection_has_explicit_low_encryption_floor(body) {
            saw_low_floor_encrypted = true;
        }
    }

    if saw_low_floor_encrypted {
        return true;
    }
    if saw_recommended {
        return false;
    }
    false
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

fn projection_has_explicit_low_encryption_floor(value: &Value) -> bool {
    let profile = projection_string_field(value, &["encryption_profile"])
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if matches!(profile.as_str(), "none" | "external") {
        return true;
    }
    let content_floor = projection_string_field(value, &["content_encryption_floor"]);
    let metadata_floor = projection_string_field(value, &["metadata_encryption_floor"]);
    [content_floor.as_deref(), metadata_floor.as_deref()]
        .into_iter()
        .flatten()
        .any(|floor| floor.trim() != crate::api::RECOMMENDED_REALM_ENCRYPTION_FLOOR)
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
    fn empty_projection_set_is_inconclusive() {
        assert!(
            !account_needs_recommended_encryption_prompt_for_projections(
                "did:web:alice.example",
                &BTreeMap::new()
            )
        );
    }

    #[test]
    fn non_realm_projection_only_is_inconclusive() {
        let mut projections = BTreeMap::new();
        projections.insert(
            "ck:notification:0196419b-0000-7000-8000-000000000001".to_owned(),
            json!({
                "__kind": "notification",
                "message": "hello"
            }),
        );

        assert!(
            !account_needs_recommended_encryption_prompt_for_projections(
                "did:web:alice.example",
                &projections
            )
        );
    }

    #[test]
    fn visible_low_floor_realm_prompts_without_pcr_projection() {
        let mut projections = BTreeMap::new();
        projections.insert(
            "ck:realm:0196419b-0000-7000-8000-000000000001".to_owned(),
            json!({
                "summary": {
                    "encryption_profile": "none"
                }
            }),
        );

        assert!(account_needs_recommended_encryption_prompt_for_projections(
            "did:web:alice.example",
            &projections
        ));
    }

    #[test]
    fn mls_realm_with_missing_floor_fields_is_inconclusive_without_pcr_projection() {
        let mut projections = BTreeMap::new();
        projections.insert(
            "ck:realm:0196419b-0000-7000-8000-000000000001".to_owned(),
            json!({
                "summary": {
                    "encryption_profile": "mls_rfc9420"
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

    #[test]
    fn explicit_allow_plaintext_floor_prompts_without_pcr_projection() {
        let mut projections = BTreeMap::new();
        projections.insert(
            "ck:realm:0196419b-0000-7000-8000-000000000001".to_owned(),
            json!({
                "summary": {
                    "encryption_profile": "mls_rfc9420",
                    "content_encryption_floor": "allow_plaintext",
                    "metadata_encryption_floor": "e2ee_required"
                }
            }),
        );

        assert!(account_needs_recommended_encryption_prompt_for_projections(
            "did:web:alice.example",
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
