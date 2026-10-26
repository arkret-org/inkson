//! G3.Y3 — Personal blocklist settings page (`/settings/blocked-users`).
//!
//! Actor-private list of blocked stable identity ids. Spec
//! `governance/content-moderation.md` §4 — personal blocklist is a
//! client-side filter; spec `discovery/client-preferences.md` §2
//! defines the `ak.account.blocklist` account_data shape.
//!
//! Surfaces:
//! - `blocked-users-panel` wrapper
//! - `blocked-users-list` list wrapper
//! - `blocked-user-row[data-actor-id, data-blocked-at]` per entry
//! - `block-target-input`, `block-user-button`, `unblock-button`
//! - `write-status`
//!
//! The `block-actor-button` testid exposed elsewhere (directory rows,
//! space member rows) is owned by the respective view modules — this
//! file only owns the settings surface.

use std::rc::Rc;

use glory::prelude::*;

use super::widgets::{input, *};
use crate::presentation::{InksonContext, View};
use crate::views::helpers::{actor_display_label, short_protocol_id};

/// `reason_code` options offered for a personal block. Mirrors the report
/// reason enum in `governance/content-moderation.md` §3.2 (`spam`,
/// `harassment`, `hate_speech`, `nsfw`, `illegal`, `misinformation`, `other`).
const BLOCK_REASON_CODES: &[&str] = &[
    "spam",
    "harassment",
    "hate_speech",
    "nsfw",
    "illegal",
    "misinformation",
    "other",
];

/// Translation key for a `target.kind` value.
fn target_kind_label_key(kind: crate::account_data::BlocklistUiTargetKind) -> &'static str {
    match kind {
        crate::account_data::BlocklistUiTargetKind::Domain => {
            "settings.privacy.blocklist.kind.domain"
        }
        crate::account_data::BlocklistUiTargetKind::Actor => {
            "settings.privacy.blocklist.kind.actor"
        }
    }
}

fn surface_label_key(
    surface: arkret_models_collaboration::objects::productivity::AccountBlocklistSurface,
) -> &'static str {
    use arkret_models_collaboration::objects::productivity::AccountBlocklistSurface;
    match surface {
        AccountBlocklistSurface::Messages => "settings.privacy.blocklist.surface.messages",
        AccountBlocklistSurface::Mentions => "settings.privacy.blocklist.surface.mentions",
        AccountBlocklistSurface::Dm => "settings.privacy.blocklist.surface.dm",
        AccountBlocklistSurface::Calls => "settings.privacy.blocklist.surface.calls",
        AccountBlocklistSurface::Contacts => "settings.privacy.blocklist.surface.contacts",
        AccountBlocklistSurface::Applets => "settings.privacy.blocklist.surface.applets",
        AccountBlocklistSurface::Presence => "settings.privacy.blocklist.surface.presence",
        AccountBlocklistSurface::Notifications => {
            "settings.privacy.blocklist.surface.notifications"
        }
        AccountBlocklistSurface::Directory => "settings.privacy.blocklist.surface.directory",
    }
}

/// Placeholder hint for the stable identifier input, by target kind.
fn target_kind_placeholder(kind: crate::account_data::BlocklistUiTargetKind) -> &'static str {
    match kind {
        crate::account_data::BlocklistUiTargetKind::Domain => "example.com",
        crate::account_data::BlocklistUiTargetKind::Actor => {
            r#"{"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:station.example"}}"#
        }
    }
}

/// Resolve a UI expiry choice to an absolute RFC 3339 timestamp. `never`
/// (and any unknown value) maps to `None` — a permanent block.
fn expiry_choice_to_rfc3339(choice: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let duration = match choice {
        "1d" => chrono::Duration::days(1),
        "7d" => chrono::Duration::days(7),
        "30d" => chrono::Duration::days(30),
        _ => return None,
    };
    Some(chrono::Utc::now() + duration)
}

fn is_valid_identity_id(kind: crate::account_data::BlocklistUiTargetKind, input: &str) -> bool {
    match kind {
        crate::account_data::BlocklistUiTargetKind::Actor => {
            serde_json::from_str::<arkret_sdk::ActorId>(input).is_ok()
        }
        crate::account_data::BlocklistUiTargetKind::Domain => !input.trim().is_empty(),
    }
}

pub(super) fn page(scope: &Scope, context: Rc<InksonContext>) -> View {
    use crate::account_data::BlocklistUiTargetKind as Kind;
    let entries = scope.cage(context.state_store.read(|store| store.client_blocklist()));
    let target_kind = scope.cage(Kind::Actor);
    let target_type = scope.cage(Kind::Actor.ui_value().to_owned());
    let target = scope.cage(String::new());
    let reason = scope.cage(String::new());
    let expiry = scope.cage("never".to_owned());
    let applies_to = scope.cage(crate::account_data::DEFAULT_BLOCKLIST_APPLIES_TO.to_vec());
    let feedback = scope.cage(String::new());
    let has_session = {
        let context = context.clone();
        scope.bond(move || !context.token.get().trim().is_empty())
    };
    let can_block = {
        let context = context.clone();
        scope.bond(move || {
            let value = target.get();
            let kind = target_kind.get();
            let valid = if kind == Kind::Actor {
                is_valid_identity_id(kind, value.trim())
            } else {
                super::is_likely_valid_domain(value.trim())
            };
            valid && !applies_to.get().is_empty() && !context.token.get().trim().is_empty()
        })
    };
    let list_context = context.clone();
    let list = reactive(entries, move |scope, list_entries| {
        let context = list_context.clone();
        if list_entries.is_empty() {
            return paragraph(
                "empty-state",
                context.translated(scope, "settings.privacy.blocklist.empty_title"),
            );
        }
        let mut children = Vec::new();
        for entry in list_entries {
            let raw = crate::account_data::blocklist_target_value(&entry.target);
            let label = context.state_store.read(|store| {
                if crate::account_data::target_is_actor(&entry.target) {
                    actor_display_label(store, &raw)
                } else {
                    short_protocol_id(&raw)
                }
            });
            let target = entry.target.clone();
            let remove_context = context.clone();
            let surfaces = entry
                .applies_to
                .iter()
                .map(|surface| context.tr(surface_label_key(*surface)))
                .collect::<Vec<_>>()
                .join(", ");
            children.push(stack(
                "event blocked-user-row",
                vec![
                    line(
                        "event-head",
                        vec![plain(label), plain(entry.created_at.to_string())],
                    ),
                    paragraph(
                        "muted",
                        crate::i18n::tr_args(
                            "settings.privacy.blocklist.applies_summary",
                            &[("surfaces", surfaces)],
                        ),
                    ),
                    paragraph(
                        "muted",
                        entry
                            .expires_at
                            .map(|value| value.to_string())
                            .unwrap_or_default(),
                    ),
                    paragraph(
                        "muted",
                        entry
                            .reason_code
                            .map(|reason| reason.to_string())
                            .unwrap_or_default(),
                    ),
                    action(
                        scope,
                        context.clone(),
                        "unblock-button",
                        "settings.privacy.blocklist.unblock",
                        "secondary",
                        has_session,
                        move || {
                            let changed = remove_context
                                .state_store
                                .write(|store| store.unblock_target(&target));
                            let next = remove_context
                                .state_store
                                .read(|store| store.client_blocklist());
                            entries.revise(|value| {
                                *value = next.clone();
                            });
                            if changed {
                                feedback.revise(|value| {
                                    *value = remove_context
                                        .tr("settings.privacy.blocklist.status.unblocked")
                                });
                                if let Some(account) = remove_context.active_account.get() {
                                    super::push_blocklist_account_data(
                                        remove_context.clone(),
                                        account.server_url.to_string(),
                                        remove_context.token.get(),
                                        account.principal_id().to_string(),
                                        remove_context.state_store.clone(),
                                        next,
                                    );
                                }
                            }
                        },
                    ),
                ],
            ));
        }
        stack("settings-list blocked-users-list", children)
    });
    let mut surfaces = Vec::new();
    for surface in crate::account_data::DEFAULT_BLOCKLIST_APPLIES_TO
        .iter()
        .copied()
    {
        surfaces.push(toggle(
            scope,
            context.clone(),
            &format!(
                "block-surface-{}",
                surface_label_key(surface)
                    .rsplit('.')
                    .next()
                    .unwrap_or("surface")
            ),
            surface_label_key(surface),
            scope.bond(move || applies_to.get().contains(&surface)),
            true,
            move |checked| {
                applies_to.revise(|values| {
                    values.retain(|value| value != &surface);
                    if checked {
                        values.push(surface);
                    }
                })
            },
        ));
    }
    let mut reasons = vec![(
        String::new(),
        context.tr("settings.privacy.blocklist.no_reason"),
    )];
    reasons.extend(BLOCK_REASON_CODES.iter().map(|code| {
        (
            code.to_string(),
            context.tr(&format!("moderation.report.reason.{code}")),
        )
    }));
    let add_context = context.clone();
    card(
        scope,
        context.clone(),
        "settings.privacy.blocklist.title",
        vec![
            list,
            card(
                scope,
                context.clone(),
                "settings.privacy.blocklist.target_type",
                vec![
                    choice(
                        scope,
                        context.clone(),
                        "block-target-kind",
                        "settings.privacy.blocklist.target_type",
                        target_type,
                        Kind::ALL
                            .iter()
                            .copied()
                            .map(|kind| {
                                (
                                    kind.ui_value().to_owned(),
                                    context.tr(target_kind_label_key(kind)),
                                )
                            })
                            .collect(),
                        true,
                        move |next| {
                            if let Some(kind) = Kind::from_ui_value(&next) {
                                target_kind.revise(|value| {
                                    *value = kind;
                                });
                                target_type.revise(|value| {
                                    *value = next;
                                });
                            }
                        },
                    ),
                    input(
                        scope,
                        context.clone(),
                        "block-target-input",
                        "settings.privacy.blocklist.target.actor",
                        target,
                        true,
                    ),
                    paragraph(
                        "muted block-target-hint",
                        scope.bond(move || target_kind_placeholder(target_kind.get()).to_owned()),
                    ),
                    stack("settings-grid compact", surfaces),
                    choice(
                        scope,
                        context.clone(),
                        "block-reason",
                        "settings.privacy.blocklist.reason_optional",
                        reason,
                        reasons,
                        true,
                        move |next| {
                            reason.revise(|value| {
                                *value = next;
                            })
                        },
                    ),
                    choice(
                        scope,
                        context.clone(),
                        "block-expiry",
                        "settings.privacy.blocklist.expires",
                        expiry,
                        ["never", "1d", "7d", "30d"]
                            .into_iter()
                            .map(|value| {
                                (
                                    value.to_owned(),
                                    context
                                        .tr(&format!("settings.privacy.blocklist.expiry.{value}")),
                                )
                            })
                            .collect(),
                        true,
                        move |next| {
                            expiry.revise(|value| {
                                *value = next;
                            })
                        },
                    ),
                    action(
                        scope,
                        context.clone(),
                        "block-user-button",
                        "settings.privacy.blocklist.block",
                        "primary",
                        can_block,
                        move || {
                            let kind = target_kind.get();
                            let raw = target.get().trim().to_owned();
                            let valid = if kind == Kind::Actor {
                                is_valid_identity_id(kind, &raw)
                            } else {
                                super::is_likely_valid_domain(&raw)
                            };
                            if !valid || applies_to.get().is_empty() {
                                return;
                            }
                            let code = reason.get().trim().to_owned();
                            let changed = add_context.state_store.write(|store| {
                                store.block_target(
                                    kind,
                                    &raw,
                                    (!code.is_empty()).then_some(code),
                                    applies_to.get(),
                                    expiry_choice_to_rfc3339(&expiry.get()),
                                )
                            });
                            let next = add_context
                                .state_store
                                .read(|store| store.client_blocklist());
                            entries.revise(|value| {
                                *value = next.clone();
                            });
                            feedback.revise(|value| {
                                *value = add_context.tr(if changed {
                                    "settings.privacy.blocklist.status.added"
                                } else {
                                    "settings.privacy.blocklist.status.duplicate"
                                })
                            });
                            if changed {
                                target.revise(|value| value.clear());
                                if let Some(account) = add_context.active_account.get() {
                                    super::push_blocklist_account_data(
                                        add_context.clone(),
                                        account.server_url.to_string(),
                                        add_context.token.get(),
                                        account.principal_id().to_string(),
                                        add_context.state_store.clone(),
                                        next,
                                    );
                                }
                            }
                        },
                    ),
                    status(feedback),
                ],
            ),
        ],
    )
}
#[cfg(test)]
mod tests {
    use super::is_valid_identity_id;

    #[test]
    fn actor_block_target_requires_full_actor_id() {
        use crate::account_data::BlocklistUiTargetKind as Kind;
        let actor = account_actor("ak:did_core:web:station.example");
        assert!(is_valid_identity_id(Kind::Actor, &actor));
        assert!(!is_valid_identity_id(
            Kind::Actor,
            "ak:did_core:web:bob.example"
        ));
        assert!(!is_valid_identity_id(
            Kind::Actor,
            r#"{"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example"}}"#
        ));
        let service = arkret_sdk::ActorId::service(
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )
        .to_string();
        assert!(is_valid_identity_id(Kind::Actor, &service));
    }

    fn account_actor(station: &str) -> String {
        arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            arkret_sdk::DidCoreId::new(station).unwrap(),
        ))
        .to_string()
    }

    #[test]
    fn blocklist_uses_client_blocklist_state_store_methods() {
        let mut store = crate::state::isolated_store_for_tests("settings-blocklist");
        assert!(store.client_blocklist().is_empty());

        let actor = account_actor("ak:did_core:web:station.example");
        assert!(!store.block_user("ak:did_core:web:bob.example", None));
        assert!(store.block_user(&actor, None));
        assert!(!store.block_user(&actor, None));

        let entries = store.client_blocklist();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            crate::account_data::blocklist_target_value(&entries[0].target),
            actor
        );
        assert!(crate::account_data::target_is_actor(&entries[0].target));
        assert_eq!(
            store.pending_personal_block_sagas(),
            std::collections::BTreeSet::from([actor.clone()])
        );
        assert!(store.personal_blocklist_write_pending());
        assert!(store.committed_personal_block_sagas().is_empty());

        let remote = entries.clone();
        store.set_client_blocklist(4, remote.clone());
        store.set_client_blocklist(3, Vec::new());
        store.set_client_blocklist(4, Vec::new());
        assert_eq!(store.client_blocklist_revision(), 4);
        assert_eq!(store.client_blocklist(), remote);
        assert!(!store.personal_blocklist_write_pending());
        assert_eq!(
            store.committed_personal_block_sagas(),
            std::collections::BTreeSet::from([actor.clone()])
        );

        store.complete_personal_block_saga(&actor);
        assert!(store.pending_personal_block_sagas().is_empty());

        assert!(store.unblock_user(&actor));
        assert!(!store.unblock_user(&actor));
        assert!(store.client_blocklist().is_empty());
    }

    #[test]
    fn block_sagas_preserve_distinct_stations_and_canonicalize_input() {
        let mut store = crate::state::isolated_store_for_tests("settings-blocklist-stations");
        let first = account_actor("ak:did_core:web:station-a.example");
        let second = account_actor("ak:did_core:web:station-b.example");
        let pretty = serde_json::to_string_pretty(
            &serde_json::from_str::<arkret_sdk::ActorId>(&first).unwrap(),
        )
        .unwrap();
        assert!(store.block_user(&pretty, None));
        assert!(!store.block_user(&first, None));
        assert!(store.block_target(
            crate::account_data::BlocklistUiTargetKind::Actor,
            &second,
            None,
            Vec::new(),
            None
        ));
        assert_eq!(
            store.pending_personal_block_sagas(),
            std::collections::BTreeSet::from([first.clone(), second.clone()])
        );
        assert!(store.unblock_user(&first));
        assert_eq!(store.client_blocklist().len(), 1);
        assert_eq!(
            crate::account_data::blocklist_target_value(&store.client_blocklist()[0].target),
            second
        );
    }

    #[test]
    fn non_dm_block_does_not_stage_contact_tombstone() {
        let mut store = crate::state::isolated_store_for_tests("settings-blocklist-non-dm");
        let actor = account_actor("ak:did_core:web:station.example");
        assert!(store.block_target(
            crate::account_data::BlocklistUiTargetKind::Actor,
            &actor,
            None,
            vec![arkret_models_collaboration::objects::productivity::AccountBlocklistSurface::Messages],
            None,
        ));
        assert!(store.pending_personal_block_sagas().is_empty());
    }

    #[test]
    fn actor_projection_cache_is_bounded_and_revision_invalidated() {
        let mut store = crate::state::isolated_store_for_tests("settings-blocklist-cache");
        let mut actors = Vec::new();
        let mut entries = Vec::new();
        for index in 0..300 {
            let actor = account_actor(&format!("ak:did_core:web:station-{index}.example"));
            entries.push(
                crate::account_data::new_blocklist_entry(
                    crate::account_data::BlocklistUiTargetKind::Actor,
                    &actor,
                    None,
                    crate::account_data::DEFAULT_BLOCKLIST_APPLIES_TO.to_vec(),
                    None,
                    chrono::Utc::now(),
                )
                .unwrap(),
            );
            actors.push(actor);
        }
        store.set_client_blocklist(7, entries);
        for actor in &actors {
            assert_eq!(store.client_blocklist_for_actor(actor).len(), 1);
        }
        assert_eq!(store.blocklist_projection_cache_len(), 256);

        store.set_client_blocklist(8, Vec::new());
        assert_eq!(store.blocklist_projection_cache_len(), 0);
        assert!(store.client_blocklist_for_actor(&actors[0]).is_empty());
        assert_eq!(store.blocklist_projection_cache_len(), 1);
    }

    #[test]
    fn tombstone_failure_resumes_without_rewriting_blocklist_revision() {
        let mut store = crate::state::isolated_store_for_tests("settings-blocklist-resume");
        let actor = account_actor("ak:did_core:web:station.example");
        assert!(store.block_user(&actor, None));
        let accepted_entries = store.client_blocklist();

        // Simulate Account Data acceptance followed by a Contact transport
        // failure: the accepted leg is durable and the write leg is no longer
        // pending, so the retry resumes at tombstone instead of minting v2.
        store.set_client_blocklist(1, accepted_entries);
        assert_eq!(store.client_blocklist_revision(), 1);
        assert!(!store.personal_blocklist_write_pending());
        assert_eq!(
            store.committed_personal_block_sagas(),
            std::collections::BTreeSet::from([actor.clone()])
        );
        assert_eq!(
            store.pending_personal_block_sagas(),
            std::collections::BTreeSet::from([actor])
        );
    }

    #[test]
    fn unblock_rebuilds_view_from_retained_history_without_restoring_contact() {
        let mut store = crate::state::isolated_store_for_tests("settings-blocklist-unblock");
        let blocked = account_actor("ak:did_core:web:blocked.example");
        let visible = account_actor("ak:did_core:web:visible.example");
        let retained_history = vec![blocked.clone(), visible.clone()];
        assert!(store.block_user(&blocked, None));
        let accepted_entries = store.client_blocklist();
        store.set_client_blocklist(1, accepted_entries);
        store.complete_personal_block_saga(&blocked);

        let projected = retained_history
            .iter()
            .filter(|actor| {
                !crate::account_data::is_blocked(&store.client_blocklist_for_actor(actor), actor)
            })
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(projected, vec![visible.clone()]);

        assert!(store.unblock_user(&blocked));
        assert!(store.personal_blocklist_write_pending());
        assert!(store.pending_personal_block_sagas().is_empty());
        let rebuilt = retained_history
            .iter()
            .filter(|actor| {
                !crate::account_data::is_blocked(&store.client_blocklist_for_actor(actor), actor)
            })
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(rebuilt, retained_history);
    }
}
