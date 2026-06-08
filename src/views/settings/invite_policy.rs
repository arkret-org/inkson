//! U4 — "谁可以邀请我" 接收策略设置 (`/settings/invite-policy`).
//!
//! Edits the actor `invite_receive_policy` (spec `invite_receive_policy`):
//! - `allowed_introduction_kinds` — which introduction-evidence kinds are
//!   accepted at all (consent_grant / locator_ref / shared_realm /
//!   same_principal_server / explicit_address).
//! - `explicit_address_behavior` — drop / quarantine / notify for raw-address
//!   invites.
//! - `disclosure.high_trust` — whether contacts learn the invite outcome.
//! - `blocked_subjects` — list of subjects barred from inviting, with removal.
//!
//! The soland self-plane endpoint (`/_cokret/self/invite-receive-policy`) is
//! still being wired; the panel connects to the real endpoint and degrades
//! gracefully — on a 404/501/405 GET it seeds the form with defaults, and a
//! failed save is surfaced inline without losing the user's edits.
//!
//! Surfaces (testids for cotest):
//! - `invite-policy-panel`
//! - `invite-policy-kind-{kind}` (checkboxes)
//! - `invite-policy-explicit-behavior` (select)
//! - `invite-policy-disclosure-high-trust` (switch)
//! - `invite-policy-blocked-row[data-subject]`, `invite-policy-unblock-{subject}`
//! - `invite-policy-save-button`, `invite-policy-status`

use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;

use crate::models::InviteReceivePolicy;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::label::Label;
use crate::ui::select::{Select, SelectOption};
use crate::ui::switch::Switch;
use crate::views::helpers::{short_protocol_id, with_authed_api};

/// Introduction-evidence kinds offered in the UI, with natural-language labels.
const INTRODUCTION_KINDS: &[(&str, &str)] = &[
    ("consent_grant", "联系人(已同意的好友)"),
    ("locator_ref", "邀请链接"),
    ("shared_realm", "同群成员"),
    ("same_principal_server", "同一服务器的用户"),
    ("explicit_address", "任何知道我地址的人"),
];

#[component]
pub fn InvitePolicySettingsCard(
    base_url: Signal<String>,
    token: Signal<String>,
) -> Element {
    let mut policy = use_signal(InviteReceivePolicy::default);
    let mut loaded = use_signal(|| false);
    let mut loading = use_signal(|| true);
    let mut status = use_signal(String::new);
    let mut saving = use_signal(|| false);

    // Hydrate from the server once. 404/501/405 → keep defaults (the endpoint
    // isn't wired on this deployment yet); any other error surfaces inline but
    // still lets the user edit + save against the real endpoint.
    {
        use_effect(move || {
            if loaded() {
                return;
            }
            loaded.set(true);
            let base = base_url();
            let api_token = token();
            spawn(async move {
                match with_authed_api(&base, api_token, |api| async move {
                    api.get_invite_receive_policy().await
                })
                .await
                {
                    Ok(outcome) => {
                        policy.set(outcome.policy);
                    }
                    Err(err) => {
                        // Graceful-degrade message; defaults stay in the form.
                        status.set(format!(
                            "未能从服务器读取现有策略(将使用默认值):{}",
                            err.display()
                        ));
                    }
                }
                loading.set(false);
            });
        });
    }

    let current = policy.read().clone();
    let explicit_behavior_selected = use_memo(move || Some(policy.read().explicit_address_behavior.clone()));
    let high_trust_outcome = current.disclosure.high_trust == "outcome";

    rsx! {
        div { class: "event", "data-testid": "invite-policy-panel",
            div { class: "event-head",
                span { "谁可以邀请我" }
                if loading() { span { "加载中…" } }
            }
            div { class: "muted",
                "选择哪些来源可以邀请你加入群组。不在允许范围内的邀请会按下面的规则丢弃或暂存待审。"
            }

            // ── allowed_introduction_kinds ───────────────────────────────
            div { class: "settings-subsection",
                strong { class: "settings-subsection-title", "允许的邀请来源" }
                div { class: "settings-list",
                    for (kind, label) in INTRODUCTION_KINDS.iter().copied() {
                        {
                            let checked = current.allowed_introduction_kinds.iter().any(|k| k == kind);
                            rsx! {
                                label { class: "metric invite-policy-kind-row",
                                    Checkbox {
                                        "data-testid": "invite-policy-kind-{kind}",
                                        checked: if checked { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                        on_checked_change: move |state: CheckboxState| {
                                            let enabled = bool::from(state);
                                            let mut next = policy.read().clone();
                                            next.allowed_introduction_kinds.retain(|k| k != kind);
                                            if enabled {
                                                next.allowed_introduction_kinds.push(kind.to_owned());
                                            }
                                            policy.set(next);
                                        },
                                    }
                                    span { " {label}" }
                                }
                            }
                        }
                    }
                }
            }

            // ── explicit_address_behavior ────────────────────────────────
            div { class: "settings-subsection",
                Label { html_for: "invite-policy-explicit-behavior", "“任何知道我地址的人”的处理方式" }
                Select::<String> {
                    id: "invite-policy-explicit-behavior",
                    "data-testid": "invite-policy-explicit-behavior",
                    value: Some(explicit_behavior_selected.into()),
                    on_value_change: move |v: Option<String>| {
                        if let Some(v) = v {
                            let mut next = policy.read().clone();
                            next.explicit_address_behavior = v;
                            policy.set(next);
                        }
                    },
                    SelectOption::<String> { index: 0usize, value: "drop".to_string(), text_value: "drop", "直接丢弃" }
                    SelectOption::<String> { index: 1usize, value: "quarantine".to_string(), text_value: "quarantine", "暂存待审" }
                    SelectOption::<String> { index: 2usize, value: "notify".to_string(), text_value: "notify", "通知我" }
                }
                div { class: "muted",
                    "未知来源的邀请将被"
                    if current.unknown_invites == "drop" { "直接丢弃" } else { "暂存待审" }
                    "。"
                }
            }

            // ── disclosure ───────────────────────────────────────────────
            div { class: "settings-subsection",
                strong { class: "settings-subsection-title", "回执" }
                label { class: "metric",
                    Switch {
                        "data-testid": "invite-policy-disclosure-high-trust",
                        checked: high_trust_outcome,
                        on_checked_change: move |checked: bool| {
                            let mut next = policy.read().clone();
                            next.disclosure.high_trust = if checked { "outcome".to_owned() } else { "opaque".to_owned() };
                            policy.set(next);
                        },
                    }
                    span { " 让联系人知道邀请结果" }
                }
                div { class: "muted",
                    "对陌生人(低信任来源)始终不回执,避免暴露你是否在线或是否接受邀请。"
                }
            }

            // ── blocked_subjects ─────────────────────────────────────────
            div { class: "settings-subsection",
                strong { class: "settings-subsection-title", "已屏蔽的邀请者" }
                if current.blocked_subjects.is_empty() {
                    div { class: "muted", "data-testid": "invite-policy-blocked-empty", "没有被屏蔽的邀请者。" }
                } else {
                    div { class: "settings-list",
                        for subject in current.blocked_subjects.iter().cloned() {
                            div {
                                class: "metric invite-policy-blocked-row",
                                "data-testid": "invite-policy-blocked-row",
                                "data-subject": "{subject}",
                                span { class: "mono", title: "{subject}", "{short_protocol_id(&subject)}" }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "invite-policy-unblock-{subject}",
                                    onclick: {
                                        let subject = subject.clone();
                                        move |_| {
                                            let mut next = policy.read().clone();
                                            next.blocked_subjects.retain(|s| s != &subject);
                                            policy.set(next);
                                            status.set("已从屏蔽列表移除,记得点击保存。".to_owned());
                                        }
                                    },
                                    "移除"
                                }
                            }
                        }
                    }
                }
            }

            div { class: "actions",
                Button {
                    variant: ButtonVariant::Primary,
                    "data-testid": "invite-policy-save-button",
                    disabled: saving(),
                    onclick: move |_| {
                        let base = base_url();
                        let api_token = token();
                        let to_save = policy.read().clone();
                        saving.set(true);
                        status.set("正在保存…".to_owned());
                        spawn(async move {
                            match with_authed_api(&base, api_token, |api| async move {
                                api.set_invite_receive_policy(&to_save).await
                            })
                            .await
                            {
                                Ok(outcome) => {
                                    policy.set(outcome.policy);
                                    status.set("已保存。".to_owned());
                                }
                                Err(err) => status.set(format!("保存失败:{}", err.display())),
                            }
                            saving.set(false);
                        });
                    },
                    if saving() { "保存中…" } else { "保存" }
                }
            }

            if !status.read().is_empty() {
                div { class: "muted", "data-testid": "invite-policy-status", "{status}" }
            }
        }
    }
}
