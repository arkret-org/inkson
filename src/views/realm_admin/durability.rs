//! Realm Recovery Key (RRK) `durability_policy` editor.
//!
//! Spec: `models/realm-and-space.md` §2.3.1 (durability_policy + write path),
//! `crypto-media/encryption-and-audit.md` §2.10.8.
//!
//! Writes the policy through `ck.realm.policy_components`
//! ([`crate::api::CokretApi::set_realm_durability_policy`]) — there is no
//! dedicated event kind. Changing the policy is a control-plane Move; the new
//! sealing obligation only takes effect once a following `ck.mls.commit` covers
//! the membership frontier, which also triggers re-disclosure. The editor
//! surfaces that two-step nature to the operator.

use cokret_sdk::Did;
use cokret_sdk::models::{
    DurabilityMode, DurabilityPolicy, DurabilityThreshold, RealmRecoveryRecipient,
};
use dioxus::prelude::*;
use serde_json::Value;

use crate::local_state::LocalStateStore;
use crate::views::helpers::with_authed_api;

/// Parse the recipient textarea: one recipient per non-empty line, fields
/// pipe-separated `recipient_id | principal_did | verification_method`. A
/// trailing 4th field is the optional `controller_organization` DID. Returns the
/// SDK-typed recipients or a human-readable parse error.
fn parse_recipients(raw: &str) -> Result<Vec<RealmRecoveryRecipient>, String> {
    let mut out = Vec::new();
    for (index, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('|').map(str::trim).collect();
        if fields.len() < 3 {
            return Err(format!(
                "line {}: expected `recipient_id | principal_did | verification_method`",
                index + 1
            ));
        }
        let principal_id = Did::new(fields[1].to_owned())
            .map_err(|err| format!("line {}: invalid principal DID: {err:?}", index + 1))?;
        let controller_organization = fields
            .get(3)
            .map(|did| did.trim())
            .filter(|did| !did.is_empty())
            .map(|did| Did::new(did.to_owned()))
            .transpose()
            .map_err(|err| {
                format!(
                    "line {}: invalid controller_organization DID: {err:?}",
                    index + 1
                )
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
) -> Result<DurabilityPolicy, String> {
    let mode = match mode {
        "none" => DurabilityMode::None,
        "org_recovery_key" => DurabilityMode::OrgRecoveryKey,
        "threshold" => DurabilityMode::Threshold,
        other => return Err(format!("unknown durability mode {other:?}")),
    };
    if matches!(mode, DurabilityMode::None) {
        return Ok(DurabilityPolicy {
            mode,
            recovery_recipients: Vec::new(),
            threshold: None,
        });
    }
    if recipients.is_empty() {
        return Err("mode != none requires at least one recovery recipient".to_owned());
    }
    // uniqueItems by recipient_id.
    let mut seen = std::collections::BTreeSet::new();
    for recipient in &recipients {
        if !seen.insert(recipient.recipient_id.clone()) {
            return Err(format!(
                "duplicate recipient_id {:?}",
                recipient.recipient_id
            ));
        }
    }
    let threshold = if matches!(mode, DurabilityMode::Threshold) {
        let n = recipients.len() as u32;
        if k == 0 || k > n {
            return Err(format!(
                "threshold k must satisfy 1 <= k <= n ({n}), got {k}"
            ));
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
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let scheme_ok = {
        let store = state_store.read();
        store
            .realm_content_scheme(&realm_id)
            .map(|scheme| scheme.trim().to_ascii_lowercase().replace('_', "-"))
            .is_some_and(|scheme| scheme == "mls-exporter-aead-v1")
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
                span { "Realm recovery key (durability)" }
                span {
                    class: if scheme_ok { "badge green" } else { "badge amber" },
                    if scheme_ok { "mls-exporter-aead-v1" } else { "scheme not eligible" }
                }
            }
            div { class: "muted",
                "声明在全体成员设备失效或全员离职后谁能解开本 Realm 历史。改策略是控制面 Move：后续 ck.mls.commit 覆盖成员前沿后才对新 epoch 生效，并触发对成员的重新披露。"
            }
            if !scheme_ok {
                div { class: "muted", "data-testid": "durability-scheme-warning",
                    "本 Realm 未使用 mls-exporter-aead-v1，无可交付的 history_secret；声明 mode != none 将被拒绝（durability_scheme_incompatible）。"
                }
            }

            label { r#for: "durability-mode-select", "Mode" }
            select {
                id: "durability-mode-select",
                "data-testid": "durability-mode-select",
                value: "{mode_value}",
                "data-value": "{mode_value}",
                onchange: move |evt| mode.set(evt.value()),
                option { value: "none", "none — 无组织恢复（丢光即永久丢失）" }
                option { value: "org_recovery_key", "org_recovery_key — 单把组织 RRK" }
                option { value: "threshold", "threshold — k-of-n 门限" }
            }

            if show_recipients {
                label { r#for: "durability-recipients-input", "Recovery recipients" }
                div { class: "muted",
                    "每行一个：recipient_id | principal_did | verification_method [ | controller_org_did]"
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
                label { r#for: "durability-threshold-k", "Threshold k (of n = recipient count)" }
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

            label { r#for: "durability-policy-revision", "Policy revision (monotonic)" }
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
                                status.set(format!("解析恢复方失败: {err}"));
                                return;
                            }
                        };
                        let policy = match build_policy(&mode_value, recipients, k) {
                            Ok(policy) => policy,
                            Err(err) => {
                                status.set(format!("策略无效: {err}"));
                                return;
                            }
                        };
                        status.set("提交中…".to_owned());
                        let result = with_authed_api(&base, session, |api| async move {
                            api.set_realm_durability_policy(&realm_id, &actor_id, &policy, revision)
                                .await
                        })
                        .await;
                        match result {
                            Ok(()) => status.set(
                                "已提交 ck.realm.policy_components；推进一次 ck.mls.commit 以激活封存并重新披露。"
                                    .to_owned(),
                            ),
                            Err(err) => status.set(format!("提交失败: {err:?}")),
                        }
                    }
                },
                "Apply durability policy"
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
