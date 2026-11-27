//! G3.Y3 — Personal blocklist settings page (`/settings/blocked-users`).
//!
//! Actor-private list of blocked stable identity ids. Spec
//! `governance/content-moderation.md` §4 — personal blocklist is a
//! client-side filter; spec `discovery/client-preferences.md` §2
//! defines the `ak.account.blocklist` account_data shape.
//!
//! The settings card exposes its title, the complete target's accessible
//! identity, and ordinary input/action controls. Directory and member-list
//! block actions are owned by their respective views.

use std::rc::Rc;

use arkret_sdk::ActorId;
use glory::prelude::*;

use super::widgets::{input, *};
use crate::account_data::BlocklistUiTargetKind;
use crate::presentation::{InksonContext, View};
use crate::views::helpers::{account_display_label, actor_display_label, short_protocol_id};

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

/// Split a complete actor identity into the same fields used for manual entry.
fn actor_fields(actor: &ActorId) -> (&'static str, &str, &str) {
    match actor {
        ActorId::Account { account_id } => (
            "actor",
            account_id.principal_id.as_str(),
            account_id.station_id.as_str(),
        ),
        ActorId::Service { service_id } => ("service", service_id.as_str(), ""),
        ActorId::Realm { realm_actor_id } => (
            "realm",
            realm_actor_id.principal_id.as_str(),
            realm_actor_id.realm_id.as_str(),
        ),
    }
}

fn form_target(
    kind: &str,
    identity: &str,
    location: &str,
) -> Option<(BlocklistUiTargetKind, String)> {
    let identity = identity.trim();
    let location = location.trim();
    if kind == "domain" {
        return super::is_likely_valid_domain(identity)
            .then(|| (BlocklistUiTargetKind::Domain, identity.to_owned()));
    }
    let principal = crate::mls_api_helpers::principal_core_id(identity).ok()?;
    let actor = match kind {
        "actor" => ActorId::account(arkret_sdk::AccountId::new(
            principal,
            crate::mls_api_helpers::principal_core_id(location).ok()?,
        )),
        "service" => ActorId::service(principal),
        "realm" => ActorId::realm(arkret_wire::RealmActorId::new(
            location.parse().ok()?,
            principal,
        )),
        _ => return None,
    };
    actor.validate().ok()?;
    Some((BlocklistUiTargetKind::Actor, actor.to_string()))
}

fn identity_text(identity: &str, location: &str) -> String {
    if location.is_empty() {
        identity.to_owned()
    } else {
        format!("{identity} @ {location}")
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

pub(super) fn page(scope: &Scope, context: Rc<InksonContext>) -> View {
    let entries = scope.cage(context.state_store.read(|store| store.client_blocklist()));
    let target_type = scope.cage("actor".to_owned());
    let location = scope.cage(String::new());
    let target = scope.cage(String::new());
    let reason = scope.cage(String::new());
    let expiry = scope.cage("never".to_owned());
    let applies_to = scope.cage(crate::account_data::DEFAULT_BLOCKLIST_APPLIES_TO.to_vec());
    let feedback = scope.cage(String::new());
    let has_session = {
        let context = context.clone();
        scope.bond(move || !context.token.get().trim().is_empty())
    };
    let selected_target =
        scope.bond(move || form_target(&target_type.get(), &target.get(), &location.get()));
    let can_block = {
        let context = context.clone();
        scope.bond(move || {
            selected_target.get().is_some()
                && !applies_to.get().is_empty()
                && !context.token.get().trim().is_empty()
        })
    };
    let list_context = context.clone();
    let list = reactive(entries, move |scope, list_entries| {
        let context = list_context.clone();
        if list_entries.is_empty() {
            return paragraph(
                "muted blocklist-empty",
                context.translated(scope, "settings.privacy.blocklist.empty_title"),
            );
        }
        let mut children = Vec::new();
        for entry in list_entries {
            let (label, identity) = match &entry.target {
                arkret_models_collaboration::objects::productivity::AccountBlocklistTarget::Actor(target) => {
                    let (_, principal, location) = actor_fields(&target.actor_id);
                    let label = context.state_store.read(|store| match &target.actor_id {
                        ActorId::Account { account_id } => account_display_label(store, account_id),
                        _ => actor_display_label(store, principal),
                    });
                    (label, identity_text(principal, location))
                }
                target => {
                    let value = crate::account_data::blocklist_target_value(target);
                    (short_protocol_id(&value), value)
                }
            };
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
                        vec![plain(label.clone()), plain(entry.created_at.to_string())],
                    ),
                    if identity == label {
                        empty()
                    } else {
                        paragraph("muted blocked-actor-identity", identity)
                    },
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
                                    *value = crate::i18n::tr_args(
                                        "settings.privacy.blocklist.status.unblocked",
                                        &[("target", label.clone())],
                                    )
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
            context.tr(&format!("moderation.reason.{code}")),
        )
    }));
    let add_context = context.clone();
    card(
        scope,
        context.clone(),
        "settings.privacy.blocklist.title",
        vec![
            list,
            stack(
                "blocklist-form",
                vec![
                    choice(
                        scope,
                        context.clone(),
                        "block-target-kind",
                        "settings.privacy.blocklist.target_type",
                        target_type,
                        ["actor", "service", "realm", "domain"]
                            .into_iter()
                            .map(|kind| {
                                (
                                    kind.to_owned(),
                                    context.tr(&format!("settings.privacy.blocklist.kind.{kind}")),
                                )
                            })
                            .collect(),
                        true,
                        move |next| {
                            if target_type.get() != next {
                                target.revise(String::clear);
                                location.revise(String::clear);
                                target_type.revise(|value| *value = next);
                            }
                        },
                    ),
                    reactive(target_type, {
                        let context = context.clone();
                        move |scope, kind| {
                            let is_domain = kind == "domain";
                            let label = match kind.as_str() {
                                "actor" => "settings.privacy.blocklist.target.actor",
                                "service" => "settings.privacy.blocklist.target.service",
                                "realm" => "settings.privacy.blocklist.target.realm_actor",
                                _ => "settings.privacy.blocklist.target.domain",
                            };
                            let mut fields = vec![field(
                                scope,
                                context.clone(),
                                "block-target-input",
                                label,
                                target,
                                true,
                                false,
                                move |next| {
                                    if !is_domain
                                        && let Ok(actor) =
                                            serde_json::from_str::<ActorId>(next.trim())
                                    {
                                        let (kind, principal, qualifier) = actor_fields(&actor);
                                        target.revise(|value| *value = principal.to_owned());
                                        location.revise(|value| *value = qualifier.to_owned());
                                        if target_type.get() != kind {
                                            target_type.revise(|value| *value = kind.to_owned());
                                        }
                                    } else {
                                        target.revise(|value| *value = next);
                                    }
                                },
                            )];
                            if kind == "actor" || kind == "realm" {
                                fields.push(input(
                                    scope,
                                    context.clone(),
                                    "block-target-location",
                                    if kind == "actor" {
                                        "settings.privacy.blocklist.target.station"
                                    } else {
                                        "settings.privacy.blocklist.target.realm"
                                    },
                                    location,
                                    true,
                                ));
                            }
                            stack("blocklist-target", fields)
                        }
                    }),
                    Box::new(
                        glory::ui::view()
                            .class("blocklist-scopes")
                            .role(glory::render::Role::Group)
                            .name(
                                context.translated(scope, "settings.privacy.blocklist.applies_to"),
                            )
                            .fill(vec![
                                paragraph(
                                    "blocklist-scopes-label",
                                    context
                                        .translated(scope, "settings.privacy.blocklist.applies_to"),
                                ),
                                stack("blocklist-applies-grid", surfaces),
                            ]),
                    ),
                    stack(
                        "blocklist-options",
                        vec![
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
                                            context.tr(&format!(
                                                "settings.privacy.blocklist.expiry.{value}"
                                            )),
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
                        ],
                    ),
                    action(
                        scope,
                        context.clone(),
                        "block-user-button",
                        "settings.privacy.blocklist.block",
                        "primary",
                        can_block,
                        move || {
                            let Some((kind, raw)) = selected_target.get() else {
                                return;
                            };
                            if applies_to.get().is_empty() {
                                return;
                            }
                            let description =
                                identity_text(target.get().trim(), location.get().trim());
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
                                let key = if changed {
                                    "settings.privacy.blocklist.status.added"
                                } else {
                                    "settings.privacy.blocklist.status.duplicate"
                                };
                                *value = crate::i18n::tr_args(key, &[("target", description)]);
                            });
                            if changed {
                                target.revise(String::clear);
                                location.revise(String::clear);
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
    #[test]
    fn account_fields_require_the_home_station() {
        let identity = "ak:did_core:web:bob.example";
        let station = "ak:did_core:web:station.example";
        assert!(super::form_target("actor", identity, "").is_none());
        assert_eq!(
            super::form_target("actor", identity, station).unwrap().1,
            account_actor(station)
        );
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
