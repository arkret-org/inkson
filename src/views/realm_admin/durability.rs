//! Realm Recovery Key (RRK) `durability_policy` editor.
//!
//! Spec: `models/realm-and-space.md` §2.3.1 (durability_policy + write path),
//! `crypto-media/encryption-and-audit.md` §2.10.8.
//!
//! Writes the policy through `ak.realm.policy_components`
//! ([`crate::transport::TransportClient::set_realm_durability_policy`]) — there is no
//! dedicated event kind. Changing the policy is a control-plane Move; the new
//! sealing obligation only takes effect once a following `ak.mls.commit` covers
//! the membership frontier, which also triggers re-disclosure. The editor
//! surfaces that two-step nature to the operator.

use arkret_models_collaboration::objects::realm::{
    DurabilityMode, DurabilityPolicy, DurabilityThreshold, RealmRecoveryRecipient,
};
use arkret_sdk::Did;
use dioxus::prelude::*;
use serde_json::Value;

use crate::i18n::tr;
use crate::state::LocalStateStore;
use crate::transport::auth::with_event_submitter;

/// Structured validation error from the form helpers. Carries the i18n key
/// plus placeholder substitutions; translation happens at the render site so
/// the helpers stay callable outside a Dioxus runtime (`tr` needs a live
/// runtime and panics in plain unit tests).
#[derive(Debug)]
struct FormError {
    key: &'static str,
    args: Vec<(&'static str, String)>,
}

impl FormError {
    fn new(key: &'static str) -> Self {
        Self {
            key,
            args: Vec::new(),
        }
    }

    fn arg(mut self, placeholder: &'static str, value: String) -> Self {
        self.args.push((placeholder, value));
        self
    }

    /// Resolve the i18n key and apply placeholder substitutions. Must be
    /// called from inside the Dioxus runtime (component/event scope).
    fn localize(&self) -> String {
        let mut message = tr(self.key);
        for (placeholder, value) in &self.args {
            message = message.replace(&format!("{{{placeholder}}}"), value);
        }
        message
    }
}

/// Parse the recipient textarea: one recipient per non-empty line, fields
/// pipe-separated `recipient_id | principal_did | verification_method`. A
/// trailing 4th field is the optional `controller_organization` DID. Returns the
/// SDK-typed recipients or a structured validation error.
fn parse_recipients(raw: &str) -> Result<Vec<RealmRecoveryRecipient>, FormError> {
    let mut out = Vec::new();
    for (index, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('|').map(str::trim).collect();
        if fields.len() < 3 {
            return Err(
                FormError::new("realm_admin.durability_err_recipient_fields")
                    .arg("line", (index + 1).to_string()),
            );
        }
        let principal_id = Did::new(fields[1].to_owned()).map_err(|err| {
            FormError::new("realm_admin.durability_err_principal_did")
                .arg("line", (index + 1).to_string())
                .arg("error", format!("{err:?}"))
        })?;
        let controller_organization = fields
            .get(3)
            .map(|did| did.trim())
            .filter(|did| !did.is_empty())
            .map(|did| Did::new(did.to_owned()))
            .transpose()
            .map_err(|err| {
                FormError::new("realm_admin.durability_err_org_did")
                    .arg("line", (index + 1).to_string())
                    .arg("error", format!("{err:?}"))
            })?;
        out.push(RealmRecoveryRecipient {
            recipient_id: fields[0].to_owned(),
            principal_id,
            verification_method: fields[2].to_owned(),
            controller_organization,
        });
    }
    Ok(out)
}

/// Validate + assemble a [`DurabilityPolicy`] from the form fields
/// (realm-and-space.md §2.3.1 constraints: `recovery_recipients` non-empty +
/// unique when `mode != none`; `1 <= k <= n == len(recipients)` for threshold).
fn build_policy(
    mode: &str,
    recipients: Vec<RealmRecoveryRecipient>,
    k: u32,
) -> Result<DurabilityPolicy, FormError> {
    let mode = match mode {
        "none" => DurabilityMode::None,
        "org_recovery_key" => DurabilityMode::OrgRecoveryKey,
        "threshold" => DurabilityMode::Threshold,
        other => {
            return Err(FormError::new("realm_admin.durability_err_unknown_mode")
                .arg("mode", format!("{other:?}")));
        }
    };
    if matches!(mode, DurabilityMode::None) {
        return Ok(DurabilityPolicy {
            mode,
            recovery_recipients: Vec::new(),
            threshold: None,
        });
    }
    if recipients.is_empty() {
        return Err(FormError::new(
            "realm_admin.durability_err_recipients_required",
        ));
    }
    // uniqueItems by recipient_id.
    let mut seen = std::collections::BTreeSet::new();
    for recipient in &recipients {
        if !seen.insert(recipient.recipient_id.clone()) {
            return Err(
                FormError::new("realm_admin.durability_err_duplicate_recipient")
                    .arg("recipient_id", format!("{:?}", recipient.recipient_id)),
            );
        }
    }
    let threshold = if matches!(mode, DurabilityMode::Threshold) {
        let n = recipients.len() as u32;
        if k == 0 || k > n {
            return Err(FormError::new("realm_admin.durability_err_threshold_k")
                .arg("n", n.to_string())
                .arg("k", k.to_string()));
        }
        Some(DurabilityThreshold { k, n })
    } else {
        None
    };
    Ok(DurabilityPolicy {
        mode,
        recovery_recipients: recipients,
        threshold,
    })
}

/// Read the projection's current `policy_components.policy_revision`, if any, so
/// the editor can default the next revision to `current + 1` (the reducer
/// rejects a stale revision). Defaults to `1` when absent.
fn current_policy_revision(store: &LocalStateStore, realm_id: &str) -> u64 {
    let state = store.load();
    let Some(body) = state.realm_tree_projections.get(realm_id.trim()) else {
        return 0;
    };
    let null = Value::Null;
    for container in [
        body,
        body.get("summary").unwrap_or(&null),
        body.get("object").unwrap_or(&null),
        body.get("realm").unwrap_or(&null),
        body.get("metadata").unwrap_or(&null),
    ] {
        if let Some(revision) = container
            .get("policy_components")
            .and_then(|components| components.get("policy_revision"))
            .or_else(|| container.get("policy_revision"))
            .and_then(Value::as_u64)
        {
            return revision;
        }
    }
    0
}

/// Durability policy editor card. Mount inside the Realm admin Security section.
#[component]
pub fn DurabilityPolicyEditor(
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let state_store = crate::app::SessionContext::get().state_store;
    let scheme_ok = {
        let store = state_store.read();
        store
            .realm_content_scheme(&realm_id)
            .map(|scheme| scheme.trim().to_ascii_lowercase().replace('_', "-"))
            .is_some_and(|scheme| scheme == "mls_exporter_aead_v1")
    };

    // Pre-fill from the current projected policy.
    let existing = state_store.read().realm_durability_policy(&realm_id);
    let initial_mode = existing
        .as_ref()
        .map(|policy| match policy.mode {
            DurabilityMode::None => "none",
            DurabilityMode::OrgRecoveryKey => "org_recovery_key",
            DurabilityMode::Threshold => "threshold",
        })
        .unwrap_or("none")
        .to_owned();
    let initial_recipients = existing
        .as_ref()
        .map(|policy| {
            policy
                .recovery_recipients
                .iter()
                .map(|recipient| {
                    let org = recipient
                        .controller_organization
                        .as_ref()
                        .map(|did| format!(" | {}", did.as_str()))
                        .unwrap_or_default();
                    format!(
                        "{} | {} | {}{org}",
                        recipient.recipient_id,
                        recipient.principal_id.as_str(),
                        recipient.verification_method
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    let initial_k = existing
        .as_ref()
        .and_then(|policy| policy.threshold.as_ref().map(|threshold| threshold.k))
        .unwrap_or(2);
    let next_revision = current_policy_revision(&state_store.read(), &realm_id) + 1;

    let mut mode = use_signal(|| initial_mode);
    let mut recipients_raw = use_signal(|| initial_recipients);
    let mut threshold_k = use_signal(|| initial_k);
    let mut policy_revision = use_signal(|| next_revision);
    let mut status = use_signal(String::new);

    let mode_value = mode();
    let show_recipients = mode_value != "none";
    let show_threshold = mode_value == "threshold";

    rsx! {
        div { class: "event", "data-testid": "realm-durability-policy-editor",
            div { class: "event-head",
                span { {tr("realm_admin.durability_title")} }
                span {
                    class: if scheme_ok { "badge green" } else { "badge amber" },
                    // The scheme identifier is a protocol literal, not translatable copy.
                    if scheme_ok { "mls_exporter_aead_v1" } else { {tr("realm_admin.durability_scheme_not_eligible")} }
                }
            }
            div { class: "muted",
                {tr("realm_admin.durability_intro")}
            }
            if !scheme_ok {
                div { class: "muted", "data-testid": "durability-scheme-warning",
                    {tr("realm_admin.durability_scheme_warning")}
                }
            }

            label { r#for: "durability-mode-select", {tr("realm_admin.durability_mode_label")} }
            select {
                id: "durability-mode-select",
                "data-testid": "durability-mode-select",
                value: "{mode_value}",
                "data-value": "{mode_value}",
                onchange: move |evt| mode.set(evt.value()),
                option { value: "none", {tr("realm_admin.durability_mode_none")} }
                option { value: "org_recovery_key", {tr("realm_admin.durability_mode_org")} }
                option { value: "threshold", {tr("realm_admin.durability_mode_threshold")} }
            }

            if show_recipients {
                label { r#for: "durability-recipients-input", {tr("realm_admin.durability_recipients_label")} }
                div { class: "muted",
                    {tr("realm_admin.durability_recipients_hint")}
                }
                textarea {
                    id: "durability-recipients-input",
                    "data-testid": "durability-recipients-input",
                    rows: "4",
                    value: "{recipients_raw}",
                    oninput: move |evt| recipients_raw.set(evt.value()),
                }
            }

            if show_threshold {
                label { r#for: "durability-threshold-k", {tr("realm_admin.durability_threshold_label")} }
                input {
                    id: "durability-threshold-k",
                    "data-testid": "durability-threshold-k",
                    r#type: "number",
                    min: "1",
                    value: "{threshold_k}",
                    oninput: move |evt| {
                        if let Ok(parsed) = evt.value().parse::<u32>() {
                            threshold_k.set(parsed);
                        }
                    },
                }
            }

            label { r#for: "durability-policy-revision", {tr("realm_admin.durability_revision_label")} }
            input {
                id: "durability-policy-revision",
                "data-testid": "durability-policy-revision",
                r#type: "number",
                min: "1",
                value: "{policy_revision}",
                oninput: move |evt| {
                    if let Ok(parsed) = evt.value().parse::<u64>() {
                        policy_revision.set(parsed);
                    }
                },
            }

            button {
                class: "primary",
                "data-testid": "durability-policy-apply",
                onclick: move |_| {
                    let base = base_url.clone();
                    let realm_id = realm_id.clone();
                    let actor_id = actor_id.clone();
                    let mode_value = mode();
                    let recipients_raw_value = recipients_raw();
                    let k = threshold_k();
                    let revision = policy_revision();
                    let session = token();
                    async move {
                        let recipients = match parse_recipients(&recipients_raw_value) {
                            Ok(recipients) => recipients,
                            Err(err) => {
                                status.set(
                                    tr("realm_admin.durability_parse_failed")
                                        .replace("{error}", &err.localize()),
                                );
                                return;
                            }
                        };
                        let policy = match build_policy(&mode_value, recipients, k) {
                            Ok(policy) => policy,
                            Err(err) => {
                                status.set(
                                    tr("realm_admin.durability_policy_invalid")
                                        .replace("{error}", &err.localize()),
                                );
                                return;
                            }
                        };
                        status.set(tr("realm_admin.durability_submitting"));
                        let result = with_event_submitter(&base, session, |sub| async move {
                            crate::transport::realm_write::set_realm_durability_policy(&sub, &realm_id, &actor_id, &policy, revision)
                                .await
                        })
                        .await;
                        match result {
                            Ok(()) => status.set(tr("realm_admin.durability_submitted")),
                            Err(err) => status.set(
                                tr("realm_admin.durability_submit_failed")
                                    .replace("{error}", &format!("{err:?}")),
                            ),
                        }
                    }
                },
                {tr("realm_admin.durability_apply_button")}
            }
            if !status().is_empty() {
                div { class: "muted", "data-testid": "durability-policy-status", "{status}" }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_recipient_lines() {
        let raw = "acme-rrk | did:web:acme.example | did:web:acme.example#rrk-1\n\
                   hr-rrk | did:web:hr.acme.example | did:web:hr.acme.example#rrk-1 | did:web:acme.example";
        let recipients = parse_recipients(raw).unwrap();
        assert_eq!(recipients.len(), 2);
        assert_eq!(recipients[0].recipient_id, "acme-rrk");
        assert_eq!(
            recipients[1]
                .controller_organization
                .as_ref()
                .unwrap()
                .as_str(),
            "did:web:acme.example"
        );
    }

    #[test]
    fn rejects_short_recipient_line() {
        assert!(parse_recipients("only-one-field").is_err());
    }

    #[test]
    fn none_mode_clears_recipients() {
        let policy = build_policy("none", Vec::new(), 0).unwrap();
        assert_eq!(policy.mode, DurabilityMode::None);
        assert!(policy.recovery_recipients.is_empty());
        assert!(policy.threshold.is_none());
    }

    #[test]
    fn threshold_requires_valid_k() {
        let recipients = parse_recipients(
            "a | did:web:a.example | did:web:a.example#k\n\
             b | did:web:b.example | did:web:b.example#k\n\
             c | did:web:c.example | did:web:c.example#k",
        )
        .unwrap();
        // k > n rejected.
        assert!(build_policy("threshold", recipients.clone(), 4).is_err());
        // valid k.
        let policy = build_policy("threshold", recipients, 2).unwrap();
        let threshold = policy.threshold.unwrap();
        assert_eq!(threshold.k, 2);
        assert_eq!(threshold.n, 3);
    }

    #[test]
    fn org_mode_requires_recipients() {
        assert!(build_policy("org_recovery_key", Vec::new(), 0).is_err());
    }

    #[test]
    fn rejects_duplicate_recipient_ids() {
        let recipients = parse_recipients(
            "dup | did:web:a.example | did:web:a.example#k\n\
             dup | did:web:b.example | did:web:b.example#k",
        )
        .unwrap();
        assert!(build_policy("org_recovery_key", recipients, 0).is_err());
    }
}
