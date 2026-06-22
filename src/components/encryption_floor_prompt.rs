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
    /// Account-level recovery state (server truth: `Some(true)` configured,
    /// `Some(false)` none, `None` unknown/loading). Whether to offer a *new*
    /// Recovery Key setup is an account decision, not a per-device one.
    account_recovery_configured: Signal<Option<bool>>,
    /// Session-scoped "Not now" flag, owned by the parent shell so it survives
    /// this component being unmounted/remounted while `active_prompt` churns
    /// during sync (e.g. a new Realm flushing in). A component-local
    /// `use_signal` would reset to `false` on every remount, so with the
    /// underlying `floor_low` condition still true the modal re-popped
    /// repeatedly during Realm creation. Hoisting it makes "Not now" stick for
    /// the rest of the session.
    mut dismissed: Signal<bool>,
) -> Element {
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
        || recovery_key_setup_prompt()
        || !account_needs_recommended_encryption_prompt(&state_store.read(), &actor)
    {
        return rsx! {};
    }

    // Whether to offer setting up a *new* 24-word Recovery Key is an
    // account-level decision, not a per-device one. Treat unknown server state
    // as not configured so the dialog never claims a Recovery Key exists before
    // the account recovery probe has completed.
    let local_recovery_configured =
        crate::views::recovery::recovery_options_configured(&state_store.read(), &actor);
    let recovery_key_configured =
        matches!(account_recovery_configured(), Some(true)) || local_recovery_configured;
    let on_enable = move |_| {
        acknowledge_dismissal(dismissed, account_did, state_store);
        if recovery_key_configured {
            status.set(String::new());
        } else {
            recovery_key_setup_prompt.set(true);
        }
    };

    rsx! {
        Dialog {
            open: true,
            on_open_change: move |open: bool| {
                if !open {
                    acknowledge_dismissal(dismissed, account_did, state_store);
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
                            acknowledge_dismissal(dismissed, account_did, state_store);
                            status.set(String::new());
                        },
                        "Not now"
                    }
                }
            }
        }
    }
}

/// Hide the advisory floor modal and remember the choice for this account.
///
/// Sets the session-scoped `dismissed` signal (immediate hide, stable across the
/// component remounting while `active_prompt` churns) and persists a per-account
/// flag so the modal auto-shows at most once — across navigations and sessions —
/// instead of re-popping on every render while `floor_low` stays true. Mirrors
/// the `RecoverySetupReminder` once-per-account suppression.
fn acknowledge_dismissal(
    mut dismissed: Signal<bool>,
    account_did: Signal<String>,
    mut state_store: Signal<LocalStateStore>,
) {
    dismissed.set(true);
    let actor = account_did();
    if !actor.trim().is_empty() {
        state_store.write().save_private_data(
            &actor,
            crate::app::ENCRYPTION_FLOOR_PROMPT_DISMISSED_KEY,
            "1".to_owned(),
        );
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
