//! Invite-quarantine UI surface.
//!
//! Lists quarantined invites when a public SDK-backed invite-quarantine
//! transport is available. The previous coauth-local admin endpoints are not
//! client-visible Cokret surfaces, so this UI currently fails closed instead of
//! constructing a private coauth transport client.
//!
//! Wire shape (coauth side):
//!
//! ```jsonc
//! {
//!   "invites": [
//!     {
//!       "invite_id": "inv-01abc",
//!       "target": "did:web:bob.example",
//!       "issuer": "did:web:alice.example",
//!       "realm_id": "ck:realm:01...",
//!       "reason": "rate_limited",
//!       "created_at": "2026-05-09T00:00:00Z",
//!       "state": "pending_review"
//!     }
//!   ]
//! }
//! ```
//!
//! `state` values: `pending_review` / `approved` / `rejected`.

use dioxus::prelude::*;
use serde_json::Value;

use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::views::helpers::short_protocol_id;

/// One quarantined invite row, parsed from the wire JSON.
#[derive(Clone, Debug, PartialEq)]
pub struct QuarantineEntry {
    pub invite_id: String,
    pub target: String,
    pub issuer: Option<String>,
    pub realm_id: Option<String>,
    pub reason: Option<String>,
    pub state: String,
}

impl QuarantineEntry {
    /// Best-effort parser for the coauth payload. Missing / malformed
    /// fields degrade to `None` / `state="unknown"` rather than
    /// erroring so the caller never has to special-case server-side
    /// shape drift.
    pub fn from_value(value: &Value) -> Option<Self> {
        let invite_id = value.get("invite_id").and_then(|v| v.as_str())?.to_owned();
        let target = value
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown target)")
            .to_owned();
        let issuer = value
            .get("issuer")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let realm_id = value
            .get("realm_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let reason = value
            .get("reason")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let state = value
            .get("state")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_owned();
        Some(Self {
            invite_id,
            target,
            issuer,
            realm_id,
            reason,
            state,
        })
    }
}

/// Top-level parser: coauth returns `{ "invites": [...] }`. Anything
/// shaped differently degrades to an empty list (the UI renders an
/// "empty" state rather than blowing up).
pub fn parse_quarantine_list(value: &Value) -> Vec<QuarantineEntry> {
    value
        .get("invites")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(QuarantineEntry::from_value).collect())
        .unwrap_or_default()
}

async fn fetch_quarantine_list(_coauth_url: &str, _is_admin: bool) -> anyhow::Result<Value> {
    anyhow::bail!(
        "invite quarantine has no SDK-backed public transport surface in inkson; private coauth admin paths are not called"
    )
}

async fn resolve_quarantine_invite(
    _coauth_url: &str,
    _invite_id: &str,
    _decision: &str,
    _reason: Option<&str>,
) -> anyhow::Result<Value> {
    anyhow::bail!(
        "invite quarantine resolution has no SDK-backed public transport surface in inkson; private coauth admin paths are not called"
    )
}

#[component]
pub fn QuarantinePanel(coauth_url: String, is_admin: bool) -> Element {
    let mut entries = use_signal(Vec::<QuarantineEntry>::new);
    let mut status = use_signal(String::new);
    let mut reject_reason = use_signal(String::new);
    let mut reject_confirm = use_signal(|| Option::<String>::None);

    let coauth_url_load = coauth_url.clone();
    let load_handler = move |_| {
        let url = coauth_url_load.clone();
        let admin = is_admin;
        spawn(async move {
            match fetch_quarantine_list(&url, admin).await {
                Ok(value) => {
                    let parsed = parse_quarantine_list(&value);
                    let count = parsed.len();
                    entries.set(parsed);
                    status.set(format!("loaded {count} entries"));
                }
                Err(err) => {
                    status.set(format!("quarantine fetch failed: {err}"));
                }
            }
        });
    };

    rsx! {
        div { class: "timeline", "data-testid": "quarantine-panel",
            div { class: "event", "data-testid": "quarantine-header",
                div { class: "event-head",
                    span { "Invite quarantine" }
                    span {
                        if is_admin {
                            "admin · all invites"
                        } else {
                            "self · your invites"
                        }
                    }
                }
                div { class: "muted",
                    if is_admin {
                        "Coauth quarantines invites that fail risk gates (rate-limited issuer, unverified email, suspicious target). Approve to release them into soland's invite pipeline; reject with reason to record an audit trail."
                    } else {
                        "Read-only view of your invites currently held for admin review. Approve / reject decisions live in the admin panel."
                    }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "quarantine-refresh-button",
                        onclick: load_handler.clone(),
                        "Refresh"
                    }
                }
                if !status().is_empty() {
                    div { class: "muted", "data-testid": "quarantine-status", "{status}" }
                }
            }
            Label { html_for: "quarantine-reject-reason-input-input", "Reject reason (used for the next reject click)" }
            Input {
                id: "quarantine-reject-reason-input-input",
                "data-testid": "quarantine-reject-reason-input",
                value: "{reject_reason}",
                placeholder: "violates issuance policy ...",
                oninput: move |event: FormEvent| reject_reason.set(event.value()),
            }
            for entry in entries() {
                div { class: "event", "data-testid": "quarantine-row",
                    div { class: "event-head",
                        {
                            let target_label = short_protocol_id(&entry.target);
                            rsx! { span { title: "{entry.target}", "{target_label}" } }
                        }
                        span { class: badge_for(&entry.state), "{entry.state}" }
                    }
                    {
                        let invite_id_label = short_protocol_id(&entry.invite_id);
                        rsx! {
                            div { class: "muted", "data-testid": "quarantine-invite-id", title: "{entry.invite_id}", "invite {invite_id_label}" }
                        }
                    }
                    if let Some(issuer) = &entry.issuer {
                        {
                            let issuer_label = short_protocol_id(issuer);
                            rsx! { div { class: "muted", title: "{issuer}", "issuer {issuer_label}" } }
                        }
                    }
                    if let Some(realm_id) = &entry.realm_id {
                        {
                            let realm_id_label = short_protocol_id(realm_id);
                            rsx! { div { class: "muted", title: "{realm_id}", "realm {realm_id_label}" } }
                        }
                    }
                    if let Some(reason) = &entry.reason {
                        div { class: "muted", "reason {reason}" }
                    }
                    if is_admin {
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "quarantine-approve-button",
                                onclick: {
                                    let url = coauth_url.clone();
                                    let invite_id = entry.invite_id.clone();
                                    move |_| {
                                        let url = url.clone();
                                        let invite_id = invite_id.clone();
                                        spawn(async move {
                                            match resolve_quarantine_invite(
                                                &url,
                                                &invite_id,
                                                "approve",
                                                Some("admin manual approval"),
                                            )
                                            .await
                                            {
                                                Ok(_) => status.set(format!(
                                                    "approved invite {}",
                                                    short_protocol_id(&invite_id)
                                                )),
                                                Err(err) => status.set(format!(
                                                    "approve {} failed: {err}",
                                                    short_protocol_id(&invite_id)
                                                )),
                                            }
                                        });
                                    }
                                },
                                "Approve"
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "quarantine-reject-button",
                                onclick: {
                                    let invite_id = entry.invite_id.clone();
                                    move |_| reject_confirm.set(Some(invite_id.clone()))
                                },
                                "Reject"
                            }
                        }
                        if reject_confirm() == Some(entry.invite_id.clone()) {
                            div { class: "event", "data-testid": "quarantine-reject-confirm",
                                div { class: "entity-title", "Reject this invite?" }
                                div { class: "muted",
                                    "Rejection is recorded in the audit trail with the reason above. The target cannot be re-invited without a new issuance."
                                }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "confirm-reject-button",
                                        onclick: {
                                            let url = coauth_url.clone();
                                            let invite_id = entry.invite_id.clone();
                                            move |_| {
                                                let url = url.clone();
                                                let invite_id = invite_id.clone();
                                                let reason_val = reject_reason();
                                                let reason_opt = if reason_val.trim().is_empty() {
                                                    None
                                                } else {
                                                    Some(reason_val.clone())
                                                };
                                                reject_confirm.set(None);
                                                spawn(async move {
                                                    match resolve_quarantine_invite(
                                                        &url,
                                                        &invite_id,
                                                        "reject",
                                                        reason_opt.as_deref(),
                                                    )
                                                    .await
                                                    {
                                                        Ok(_) => status.set(format!(
                                                            "rejected invite {}",
                                                            short_protocol_id(&invite_id)
                                                        )),
                                                        Err(err) => status.set(format!(
                                                            "reject {} failed: {err}",
                                                            short_protocol_id(&invite_id)
                                                        )),
                                                    }
                                                });
                                            }
                                        },
                                        "Confirm Reject"
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "cancel-reject-button",
                                        onclick: move |_| reject_confirm.set(None),
                                        "Cancel"
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if entries().is_empty() {
                div { class: "muted", "data-testid": "quarantine-empty",
                    "No quarantined invites — refresh to fetch latest."
                }
            }
        }
    }
}

fn badge_for(state: &str) -> &'static str {
    match state {
        "pending_review" => "badge amber",
        "approved" => "badge green",
        "rejected" => "badge red",
        _ => "badge",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_invite_shape() {
        let raw = serde_json::json!({
            "invites": [
                {
                    "invite_id": "inv-01abc",
                    "target": "did:web:bob.example",
                    "issuer": "did:web:alice.example",
                    "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                    "reason": "rate_limited",
                    "state": "pending_review"
                }
            ]
        });
        let entries = parse_quarantine_list(&raw);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].invite_id, "inv-01abc");
        assert_eq!(entries[0].target, "did:web:bob.example");
        assert_eq!(entries[0].issuer.as_deref(), Some("did:web:alice.example"));
        assert_eq!(entries[0].state, "pending_review");
        assert_eq!(badge_for(&entries[0].state), "badge amber");
    }

    #[test]
    fn missing_invites_field_degrades_to_empty() {
        let raw = serde_json::json!({});
        assert!(parse_quarantine_list(&raw).is_empty());
        let raw = serde_json::json!({"invites": null});
        assert!(parse_quarantine_list(&raw).is_empty());
    }

    #[test]
    fn entry_with_missing_invite_id_is_dropped() {
        let raw = serde_json::json!({
            "invites": [
                { "target": "did:web:bob.example", "state": "pending_review" }
            ]
        });
        // Without invite_id we cannot uniquely address the row → drop.
        assert!(parse_quarantine_list(&raw).is_empty());
    }

    #[test]
    fn entry_with_missing_optional_fields_uses_defaults() {
        let raw = serde_json::json!({
            "invites": [
                { "invite_id": "inv-02" }
            ]
        });
        let entries = parse_quarantine_list(&raw);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].invite_id, "inv-02");
        assert_eq!(entries[0].target, "(unknown target)");
        assert!(entries[0].issuer.is_none());
        assert!(entries[0].realm_id.is_none());
        assert!(entries[0].reason.is_none());
        assert_eq!(entries[0].state, "unknown");
        assert_eq!(badge_for(&entries[0].state), "badge");
    }

    #[test]
    fn approved_and_rejected_states_get_distinct_badges() {
        assert_eq!(badge_for("approved"), "badge green");
        assert_eq!(badge_for("rejected"), "badge red");
        assert_eq!(badge_for("pending_review"), "badge amber");
    }
}
