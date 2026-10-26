//! U4 - "who can invite me" receive-policy settings (`/settings/invite-policy`).
//!
//! Edits the actor `invite_receive_policy` (spec `invite-addressing.md` §5,
//! authoritative `arkret_sdk::InviteReceivePolicy`):
//! - `holder_allowed_introduction_kinds` — which introduction-evidence kinds are accepted at all
//!   (consent_grant / locator_ref / shared_realm / same_station / explicit_address).
//! - `explicit_address_behavior` — drop / quarantine / notify for raw-address invites.
//! - `disclosure.high_trust` — whether contacts learn the invite outcome.
//! - `denied_actor_ids` — exact actors barred from inviting, with removal.
//!
//! the form edits a `arkret_sdk::InviteReceivePolicy` held whole in
//! a signal. On GET we keep the *entire* server policy (including the
//! `trusted_*` / `denied_source_ids` lists this form does not surface);
//! on SET we stamp the required schema constant and exact active account_id
//! and post the same object back, so server-stored lists survive the round-trip
//! and the body satisfies the coland handler (which deserialises the SDK type
//! with deny_unknown_fields and enforces account_id == session account).
//!
//! The coland self-plane endpoint (`/_arkret/self/invite-receive-policy`)
//! degrades gracefully — on a 404/501/405 GET it seeds the form with defaults,
//! and a failed save is surfaced inline without losing the user's edits.
//!
//! Surfaces (testids for cotest):
//! - `invite-policy-panel`
//! - `invite-policy-kind-{kind}` (checkboxes)
//! - `invite-policy-explicit-behavior` (select)
//! - `invite-policy-disclosure-high-trust` (switch)
//! - `invite-policy-blocked-row[data-subject]`, `invite-policy-unblock-{subject}`
//! - `invite-policy-save-button`, `invite-policy-status`

use std::rc::Rc;

use arkret_wire::SchemaId;
use glory::prelude::*;

use super::widgets::*;
use crate::i18n::tr;
use crate::models::{DisclosureLevel, DisclosurePolicy, InviteReceiveAction, InviteReceivePolicy};
use crate::presentation::{InksonContext, View};
use crate::transport::auth::{with_authed_api, with_authed_sdk_client};
use crate::views::helpers::short_protocol_id;

/// Introduction-evidence kinds offered in the UI, paired with the i18n key for
/// their natural-language label (looked up via the active locale).
const INTRODUCTION_KINDS: &[(&str, &str)] = &[
    ("consent_grant", "invite_policy.kind.consent_grant"),
    ("locator_ref", "invite_policy.kind.locator_ref"),
    ("shared_realm", "invite_policy.kind.shared_realm"),
    ("handle_claim", "invite_policy.kind.handle_claim"),
    ("same_station", "invite_policy.kind.same_station"),
    ("explicit_address", "invite_policy.kind.explicit_address"),
];

/// Keep example guidance visible without changing the controlled input value.
fn domain_field(
    scope: &Scope,
    context: Rc<InksonContext>,
    key: &str,
    label_key: &str,
    example_key: &str,
    value: Cage<String>,
    enabled: Bond<bool>,
) -> View {
    stack(
        "field invite-policy-domain-field",
        vec![
            plain(context.translated(scope, label_key)),
            input_prompt(
                scope,
                context.translated(scope, example_key).into(),
                value,
                Box::new(
                    sapid::text_field()
                        .unstyled()
                        .class(format!("input {key}"))
                        .name(context.translated(scope, label_key))
                        .value(value)
                        .enabled(enabled)
                        .on_value_change(move |next| value.revise(|value| *value = next)),
                ),
            ),
        ],
    )
}

/// Map the `explicit_address_behavior` enum to/from the Select's string value.
fn explicit_behavior_to_str(action: &InviteReceiveAction) -> &'static str {
    match action {
        InviteReceiveAction::Drop => "drop",
        InviteReceiveAction::Quarantine => "quarantine",
        InviteReceiveAction::Notify => "notify",
    }
}

fn explicit_behavior_from_str(value: &str) -> Option<InviteReceiveAction> {
    match value {
        "drop" => Some(InviteReceiveAction::Drop),
        "quarantine" => Some(InviteReceiveAction::Quarantine),
        "notify" => Some(InviteReceiveAction::Notify),
        _ => None,
    }
}

/// Whether the high-trust disclosure tier is set to `outcome` (let contacts
/// learn the invite result). Absent disclosure / absent tier defaults to the
/// recommended `outcome`.
fn high_trust_is_outcome(policy: &InviteReceivePolicy) -> bool {
    policy
        .disclosure
        .as_ref()
        .and_then(|d| d.high_trust.as_ref())
        .map(|level| matches!(level, DisclosureLevel::Outcome))
        .unwrap_or(true)
}

fn discovery_trust_is_outcome(policy: &InviteReceivePolicy) -> bool {
    policy
        .disclosure
        .as_ref()
        .and_then(|d| d.discovery_trust.as_ref())
        .map(|level| matches!(level, DisclosureLevel::Outcome))
        .unwrap_or(false)
}

fn list_to_text(list: &[String]) -> String {
    list.join(", ")
}

fn parse_list(value: &str) -> Vec<String> {
    let mut list = Vec::new();
    for item in value
        .split([',', '\n', ';'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let item = item.to_ascii_lowercase();
        if !list.iter().any(|existing| existing == &item) {
            list.push(item);
        }
    }
    list
}

fn introduction_kind_label(kind: &str) -> String {
    INTRODUCTION_KINDS
        .iter()
        .find(|(value, _)| *value == kind)
        .map(|(_, key)| tr(key))
        .unwrap_or_else(|| kind.to_owned())
}

fn behavior_label(action: &InviteReceiveAction) -> String {
    tr(match action {
        InviteReceiveAction::Drop => "invite_policy.explicit.drop",
        InviteReceiveAction::Quarantine => "invite_policy.explicit.quarantine",
        InviteReceiveAction::Notify => "invite_policy.explicit.notify",
    })
}

fn constraints_lines(constraints: &arkret_wire::ReceivePolicyConstraints) -> Vec<String> {
    let mut lines = Vec::new();
    let mut push = |key, values| lines.push(crate::i18n::tr_args(key, &[("values", values)]));
    if let Some(kinds) = constraints.deployment_allowed_introduction_kinds.as_ref() {
        push(
            "invite_policy.constraints.permitted",
            kinds
                .iter()
                .map(|kind| introduction_kind_label(kind))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    if !constraints.deployment_denied_introduction_kinds.is_empty() {
        push(
            "invite_policy.constraints.forbidden",
            constraints
                .deployment_denied_introduction_kinds
                .iter()
                .map(|kind| introduction_kind_label(kind))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    if let Some(action) = constraints.handle_claim_max_behavior.as_ref() {
        push(
            "invite_policy.constraints.handle_cap",
            behavior_label(action),
        );
    }
    if let Some(action) = constraints.explicit_address_max_behavior.as_ref() {
        push(
            "invite_policy.constraints.explicit_cap",
            behavior_label(action),
        );
    }
    if let Some(domains) = constraints.allowed_handle_domains.as_ref() {
        push("invite_policy.constraints.domains", domains.join(", "));
    }
    if let Some(services) = constraints.trusted_directory_ids.as_ref() {
        push(
            "invite_policy.constraints.directories",
            services
                .iter()
                .map(|did| did.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    lines
}

fn subsection(scope: &Scope, context: Rc<InksonContext>, title: &str, children: Vec<View>) -> View {
    let mut nodes = vec![paragraph(
        "settings-subsection-title",
        context.translated(scope, title),
    )];
    nodes.extend(children);
    stack("settings-subsection", nodes)
}

pub(super) fn page(scope: &Scope, context: Rc<InksonContext>) -> View {
    let Some(account) = context.active_account.get() else {
        return paragraph(
            "error",
            context.translated(scope, "invite_policy.no_account"),
        );
    };
    let policy = scope.cage(InviteReceivePolicy::spec_default(account.authority.clone()));
    let loading = scope.cage(true);
    let saving = scope.cage(false);
    let feedback = scope.cage(("", Vec::<(&'static str, String)>::new()));
    let constraints = scope.cage(None::<arkret_wire::ReceivePolicyConstraints>);
    let allowed = scope.cage(String::new());
    let denied = scope.cage(String::new());
    let explicit = scope.cage("quarantine".to_owned());
    let handle = scope.cage("quarantine".to_owned());
    let generation = context.session_generation.get();
    let session = Some(account.clone());
    let token = context.token.get();
    let load_context = context.clone();
    let load_account = account.clone();
    spawn(scope, async move {
        let subject = load_account.authority.clone();
        let result = with_authed_api(load_account.server_url.as_str(), token, |api| async move {
            let constraints = api
                .describe()
                .await
                .ok()
                .and_then(|description| description.receive_policy_constraints);
            let policy = crate::transport::account::get_invite_receive_policy(
                &api.sdk_http_client()?,
                &subject,
            )
            .await?;
            Ok((policy, constraints))
        })
        .await;
        if !load_context.session_matches(generation, &session) {
            return;
        }
        match result {
            Ok((server, caps)) => {
                allowed.revise(|value| {
                    *value = list_to_text(&server.allowed_handle_domains);
                });
                denied.revise(|value| {
                    *value = list_to_text(&server.denied_handle_domains);
                });
                explicit.revise(|value| {
                    *value = explicit_behavior_to_str(&server.explicit_address_behavior).to_owned()
                });
                handle.revise(|value| {
                    *value = explicit_behavior_to_str(
                        &server
                            .handle_claim_behavior
                            .clone()
                            .unwrap_or(InviteReceiveAction::Quarantine),
                    )
                    .to_owned()
                });
                policy.revise(|value| {
                    *value = server;
                });
                constraints.revise(|value| {
                    *value = caps;
                });
            }
            Err(error) => feedback.revise(|value| {
                *value = (
                    "invite_policy.load_failed",
                    super::capabilities::api_error_feedback_args(&error),
                )
            }),
        }
        loading.revise(|value| {
            *value = false;
        });
    });
    let enabled = scope.bond(move || !saving.get());
    let mut kinds = Vec::new();
    for (kind, label_key) in INTRODUCTION_KINDS.iter().copied() {
        let checked = scope.bond(move || {
            policy
                .get()
                .holder_allowed_introduction_kinds
                .iter()
                .any(|value| value == kind)
        });
        kinds.push(stack(
            "metric invite-policy-kind-row",
            vec![toggle(
                scope,
                context.clone(),
                &format!("invite-policy-kind-{kind}"),
                label_key,
                checked,
                enabled,
                move |enabled| {
                    policy.revise(|policy| {
                        policy
                            .holder_allowed_introduction_kinds
                            .retain(|value| value != kind);
                        if enabled {
                            policy
                                .holder_allowed_introduction_kinds
                                .push(kind.to_owned());
                        }
                    })
                },
            )],
        ));
    }
    let options = || {
        ["drop", "quarantine", "notify"]
            .into_iter()
            .map(|value| {
                (
                    value.to_owned(),
                    context.tr(&format!("invite_policy.explicit.{value}")),
                )
            })
            .collect()
    };
    let handle_choice = choice(
        scope,
        context.clone(),
        "invite-policy-handle-behavior",
        "invite_policy.handle_label",
        handle,
        options(),
        enabled,
        move |next| {
            if let Some(action) = explicit_behavior_from_str(&next) {
                handle.revise(|value| {
                    *value = next;
                });
                policy.revise(|value| value.handle_claim_behavior = Some(action));
            }
        },
    );
    let explicit_choice = choice(
        scope,
        context.clone(),
        "invite-policy-explicit-behavior",
        "invite_policy.explicit_label",
        explicit,
        options(),
        enabled,
        move |next| {
            if let Some(action) = explicit_behavior_from_str(&next) {
                explicit.revise(|value| {
                    *value = next;
                });
                policy.revise(|value| value.explicit_address_behavior = action);
            }
        },
    );
    let high_trust = scope.bond(move || high_trust_is_outcome(&policy.get()));
    let discovery = scope.bond(move || discovery_trust_is_outcome(&policy.get()));
    let blocked_context = context.clone();
    let blocked_source = scope.bond(move || policy.get().denied_actor_ids);
    let blocked = reactive(blocked_source, move |scope, actors| {
        let context = blocked_context.clone();
        let mut children = Vec::new();
        if actors.is_empty() {
            children.push(paragraph(
                "muted",
                context.translated(scope, "invite_policy.blocked_empty"),
            ));
        }
        for actor in actors {
            let encoded = serde_json::to_string(&actor).unwrap_or_default();
            children.push(line(
                "metric invite-policy-blocked-row",
                vec![
                    plain(short_protocol_id(&encoded)),
                    action(
                        scope,
                        context.clone(),
                        "invite-policy-unblock",
                        "invite_policy.unblock",
                        "secondary",
                        enabled,
                        move || {
                            policy.revise(|value| {
                                value.denied_actor_ids.retain(|value| value != &actor)
                            });
                            feedback.revise(|value| {
                                *value = ("invite_policy.unblocked_hint", vec![]);
                            });
                        },
                    ),
                ],
            ));
        }
        subsection(scope, context, "invite_policy.blocked_title", children)
    });
    let caps_context = context.clone();
    let caps = reactive(constraints, move |scope, caps| {
        let Some(caps) = caps else { return empty() };
        let context = caps_context.clone();
        let lines = constraints_lines(&caps)
            .into_iter()
            .map(|value| paragraph("muted mono", value))
            .collect();
        subsection(scope, context, "invite_policy.server_caps_title", lines)
    });
    let weak = scope.downgrade();
    let save_context = context.clone();
    let save = action(
        scope,
        context.clone(),
        "invite-policy-save-button",
        "invite_policy.save",
        "primary",
        enabled,
        move || {
            if saving.get_untracked() {
                return;
            }
            let context = save_context.clone();
            let Some(account) = context.active_account.get() else {
                return;
            };
            let mut to_save = policy.get();
            to_save.schema = SchemaId::INVITE_RECEIVE_POLICY_V1.to_owned();
            to_save.account_id = account.authority.clone();
            to_save.allowed_handle_domains = parse_list(&allowed.get());
            to_save.denied_handle_domains = parse_list(&denied.get());
            let generation = context.session_generation.get();
            let session = Some(account.clone());
            let token = context.token.get();
            let Some(scope) = weak.upgrade() else { return };
            saving.revise(|value| {
                *value = true;
            });
            feedback.revise(|value| {
                *value = ("invite_policy.saving", vec![]);
            });
            spawn(&scope, async move {
                let result =
                    with_authed_sdk_client(account.server_url.as_str(), token, |http| async move {
                        crate::transport::account::set_invite_receive_policy(&http, &to_save).await
                    })
                    .await;
                if !context.session_matches(generation, &session) {
                    return;
                }
                match result {
                    Ok(server) => {
                        policy.revise(|value| {
                            *value = server;
                        });
                        feedback.revise(|value| {
                            *value = ("invite_policy.saved", vec![]);
                        });
                    }
                    Err(error) => feedback.revise(|value| {
                        *value = (
                            "invite_policy.save_failed",
                            super::capabilities::api_error_feedback_args(&error),
                        )
                    }),
                }
                saving.revise(|value| {
                    *value = false;
                });
            });
        },
    );
    let unknown_context = context.clone();
    let unknown_hint = scope.bond(move || {
        let action = if matches!(
            policy.get().unknown_invites,
            crate::models::UnknownInviteAction::Drop
        ) {
            "invite_policy.unknown_drop"
        } else {
            "invite_policy.unknown_quarantine"
        };
        format!(
            "{}{}{}",
            unknown_context.tr("invite_policy.unknown_prefix"),
            unknown_context.tr(action),
            unknown_context.tr("invite_policy.unknown_suffix")
        )
    });
    stack(
        "event invite-policy-panel",
        vec![
            line(
                "event-head",
                vec![plain(context.translated(scope, "invite_policy.title"))],
            ),
            paragraph("muted", context.translated(scope, "invite_policy.intro")),
            subsection(
                scope,
                context.clone(),
                "invite_policy.kinds_title",
                vec![stack("settings-list", kinds)],
            ),
            stack(
                "settings-subsection",
                vec![
                    handle_choice,
                    line(
                        "settings-grid compact invite-policy-domain-fields",
                        vec![
                            domain_field(
                                scope,
                                context.clone(),
                                "invite-policy-handle-allowed-domains",
                                "invite_policy.handle_allowed_domains",
                                "invite_policy.allowed_domains_example",
                                allowed,
                                enabled,
                            ),
                            domain_field(
                                scope,
                                context.clone(),
                                "invite-policy-handle-blocked-domains",
                                "invite_policy.handle_blocked_domains",
                                "invite_policy.blocked_domains_example",
                                denied,
                                enabled,
                            ),
                        ],
                    ),
                    paragraph(
                        "muted",
                        context.translated(scope, "invite_policy.handle_hint"),
                    ),
                ],
            ),
            stack(
                "settings-subsection",
                vec![
                    explicit_choice,
                    paragraph("muted invite-policy-unknown-hint", unknown_hint),
                ],
            ),
            subsection(
                scope,
                context.clone(),
                "invite_policy.disclosure_title",
                vec![
                    switch_toggle(
                        scope,
                        context.clone(),
                        "invite-policy-disclosure-high-trust",
                        "invite_policy.disclosure_toggle",
                        high_trust,
                        enabled,
                        move |checked| {
                            policy.revise(|policy| {
                                let disclosure =
                                    policy.disclosure.get_or_insert(DisclosurePolicy {
                                        high_trust: None,
                                        discovery_trust: None,
                                        low_trust: None,
                                    });
                                disclosure.high_trust = Some(if checked {
                                    DisclosureLevel::Outcome
                                } else {
                                    DisclosureLevel::Opaque
                                });
                            })
                        },
                    ),
                    switch_toggle(
                        scope,
                        context.clone(),
                        "invite-policy-disclosure-discovery-trust",
                        "invite_policy.discovery_disclosure_toggle",
                        discovery,
                        enabled,
                        move |checked| {
                            policy.revise(|policy| {
                                let disclosure =
                                    policy.disclosure.get_or_insert(DisclosurePolicy {
                                        high_trust: None,
                                        discovery_trust: None,
                                        low_trust: None,
                                    });
                                disclosure.discovery_trust = Some(if checked {
                                    DisclosureLevel::Outcome
                                } else {
                                    DisclosureLevel::Opaque
                                });
                            })
                        },
                    ),
                    paragraph(
                        "muted",
                        context.translated(scope, "invite_policy.disclosure_hint"),
                    ),
                ],
            ),
            caps,
            blocked,
            line("actions", vec![save]),
            status(scope.bond(move || {
                let (key, args) = feedback.get();
                if key.is_empty() {
                    String::new()
                } else {
                    crate::i18n::tr_args(key, &super::capabilities::localized_feedback_args(&args))
                }
            })),
        ],
    )
}
