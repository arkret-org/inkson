//! Realm Recovery Key (RRK) durability disclosure banner.
//!
//! Spec: `crypto-media/encryption-and-audit.md` §2.10.8 (disclosure obligation),
//! `models/realm-and-space.md` §2.3.1, `identity/identity-did.md` §8.3.
//!
//! When a Realm's effective `durability_policy.mode != none` (and it uses
//! `content_scheme=mls_exporter_aead_v1`), members MUST be shown a persistent
//! disclosure of the configured recovery policy. Until the client has a
//! verified coverage ledger, the banner must not claim that sealing or
//! delivery has completed.
//!
//! Two hard rules from §2.10.8 are enforced here:
//!
//! 1. **MUST NOT** phrase the holder as listening in real time or imply that a configured policy
//!    proves delivery.
//! 2. The recovery holder identity is rendered only AFTER verifying it resolves to an active
//!    `ArkretRealmHistoryRecoveryKey` service entry on the principal's DID Document (via the SDK
//!    authority `resolve_realm_history_recovery_key`). An unverifiable recipient is shown as
//!    "无法验证" / "Unverifiable" — never as a bare public key.
//!
//! All copy lives in the `durability_banner.*` i18n keys (`src/i18n/en.rs` /
//! `zh.rs`); both locales preserve the two rules above.

use dioxus::prelude::*;

use crate::mls::durability::durability_mode_label;
use crate::views::helpers::short_protocol_id;

/// Per-recipient verification status for the disclosure list.
#[derive(Clone, PartialEq, Eq)]
enum RecipientVerification {
    /// Resolved + verified against an active RRK service entry. Carries the
    /// display identity (handle / DID), never a bare key.
    Verified {
        recipient_id: String,
        principal_did: String,
        display: String,
        controller_organization: Option<String>,
    },
    /// Could not resolve / verify the RRK service entry (fail-closed). Shown as
    /// The unverifiable state does not assert an identity or possession that
    /// was not proven.
    Unverified {
        recipient_id: String,
        principal_did: String,
    },
}

/// Disclosure banner. Renders nothing unless `realm_id`'s effective durability
/// is RRK-active. Mount inside the Realm admin / conversation surface.
#[component]
pub fn DurabilityDisclosureBanner(realm_id: String) -> Element {
    // A4 — state_store from session context instead of a prop.
    let state_store = crate::app::SessionContext::get().state_store;
    // Read the policy + scheme gate synchronously from the local projection.
    let policy = {
        let store = state_store.read();
        if !store.realm_durability_is_rrk_active(&realm_id) {
            return rsx! {};
        }
        store.realm_durability_policy(&realm_id)
    };
    let Some(policy) = policy else {
        return rsx! {};
    };
    let Some(mode_label) = durability_mode_label(&policy) else {
        return rsx! {};
    };

    // Asynchronously resolve + verify each recovery recipient's identity. The
    // resource re-runs when the recipient set changes. DID documents are public
    // (`did.json`), so a fresh unauthenticated client is sufficient for the
    // service-entry designation check.
    let recipients = policy.recovery_recipients.clone();
    let verifications = use_resource(move || {
        let recipients = recipients.clone();
        async move {
            // Resolve + verify orchestration lives in `mls::durability`; the
            // component only maps the typed check results onto the display
            // enum (handle vs short DID). A fresh unauthenticated client is
            // fine — recovery-recipient DID documents are public `did.json`.
            let http = reqwest::Client::new();
            let checks =
                crate::mls::durability::verify_recovery_recipients(&http, &recipients).await;
            checks
                .into_iter()
                .map(|check| {
                    if check.verified {
                        let display = short_protocol_id(&check.principal_did);
                        RecipientVerification::Verified {
                            recipient_id: check.recipient_id,
                            principal_did: check.principal_did,
                            display,
                            controller_organization: check.controller_organization,
                        }
                    } else {
                        RecipientVerification::Unverified {
                            recipient_id: check.recipient_id,
                            principal_did: check.principal_did,
                        }
                    }
                })
                .collect::<Vec<RecipientVerification>>()
        }
    });

    let mode_human = match mode_label {
        "org_recovery_key" => "组织恢复策略已配置",
        "threshold" => "门限策略暂不支持",
        _ => mode_label,
    };

    // Snapshot the resource value so the rsx body matches on an owned Option
    // rather than borrowing the resource across the macro expansion.
    let verification_snapshot: Option<Vec<RecipientVerification>> = verifications.read().clone();

    rsx! {
        div {
            class: "event durability-disclosure-banner",
            "data-testid": "durability-disclosure-banner",
            "data-durability-mode": "{mode_label}",
            div { class: "event-head",
                span { "本 Realm 已配置历史恢复策略" }
                span {
                    class: "badge amber",
                    "data-testid": "durability-mode-badge",
                    "{mode_human} · 客户端能力待就绪"
                }
            }
            div { class: "muted",
                "当前客户端尚不能验证历史密钥是否已完整封存或交付给恢复方；本机会保留可用的历史密钥材料，但不得据此认定恢复方已经持有全部历史。"
            }
            div {
                class: "durability-recipient-list",
                "data-testid": "durability-recipient-list",
                match verification_snapshot {
                    None => rsx! {
                        div { class: "muted", "data-testid": "durability-recipients-loading",
                            {crate::i18n::tr("durability_banner.verifying")}
                        }
                    },
                    Some(list) => rsx! {
                        for verification in list {
                            {
                                match verification {
                                    RecipientVerification::Verified {
                                        recipient_id,
                                        principal_did,
                                        display,
                                        controller_organization,
                                    } => {
                                        let controlled_by = controller_organization.map(|org| {
                                            format!(
                                                " · {}",
                                                crate::i18n::tr_args(
                                                    "durability_banner.controlled_by",
                                                    &[("org", short_protocol_id(&org))],
                                                )
                                            )
                                        });
                                        rsx! {
                                            div {
                                                class: "durability-recipient",
                                                "data-testid": "durability-recipient-verified",
                                                "data-recipient-id": "{recipient_id}",
                                                span { class: "badge green", {crate::i18n::tr("durability_banner.verified")} }
                                                strong { title: "{principal_did}", "{display}" }
                                                if let Some(controlled_by) = controlled_by {
                                                    span { class: "muted", "{controlled_by}" }
                                                }
                                            }
                                        }
                                    },
                                    RecipientVerification::Unverified {
                                        recipient_id,
                                        principal_did,
                                    } => {
                                        // Never render a bare public key; only the
                                        // (unverified) principal id, clearly marked
                                        // as unverifiable ("无法验证" / "Unverifiable").
                                        let unverified_detail = crate::i18n::tr_args(
                                            "durability_banner.unverifiable_detail",
                                            &[("did", short_protocol_id(&principal_did))],
                                        );
                                        rsx! {
                                            div {
                                                class: "durability-recipient durability-recipient--unverified",
                                                "data-testid": "durability-recipient-unverified",
                                                "data-recipient-id": "{recipient_id}",
                                                span { class: "badge red", {crate::i18n::tr("durability_banner.unverifiable")} }
                                                span { class: "muted", title: "{principal_did}", "{unverified_detail}" }
                                            }
                                        }
                                    },
                                }
                            }
                        }
                    },
                }
            }
        }
    }
}
