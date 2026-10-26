use std::rc::Rc;

use arkret_sdk::events::EventKind;
use arkret_wire::SchemaId;
use glory::Scope;
use serde_json::Value;

use super::data::*;
use crate::i18n::tr;
use crate::models::RealmTreeNodeKind;
use crate::presentation::{InksonContext, View};
use crate::transport::auth::authed_api;
use crate::views::helpers::short_protocol_id;
use crate::views::settings::widgets::*;
#[derive(Clone)]
struct SpaceStatusStrings {
    created: String,
    archived: String,
    restored: String,
    tombstoned: String,
    create_failed: String,
    archive_failed: String,
    restore_failed: String,
    tombstone_failed: String,
    invalid_base_url: String,
}

impl SpaceStatusStrings {
    fn resolve() -> Self {
        Self {
            created: tr("setup.space.state.created"),
            archived: tr("setup.space.state.archived"),
            restored: tr("setup.space.state.restored"),
            tombstoned: tr("setup.space.state.tombstoned"),
            create_failed: tr("setup.space.error.create_failed"),
            archive_failed: tr("setup.space.error.archive_failed"),
            restore_failed: tr("setup.space.error.restore_failed"),
            tombstone_failed: tr("setup.space.error.tombstone_failed"),
            invalid_base_url: tr("setup.space.error.invalid_base_url"),
        }
    }

    fn fill(template: &str, args: &[(&'static str, String)]) -> String {
        crate::i18n::substitute_args(template.to_owned(), args)
    }
}

impl super::SetupDraft {
    pub(super) fn create_space(self, context: Rc<InksonContext>) {
        let token = context.token;
        let _active_account = context.active_account;
        let _selected_realm_id = context.selected_realm_id;
        let _account_recovery_configured = context.account_recovery_configured;
        let _realm_tree_nodes = context.realm_tree_nodes;
        let _new_space_context_node = context.new_space_context_node;
        let state_store = context.state_store.clone();
        let base_url = context.base_url.get_untracked();
        let _plaintext_service_id = context
            .server_description
            .get_untracked()
            .as_ref()
            .map(|description| description.service_id.as_str().to_owned())
            .unwrap_or_default();
        let _create_step = self.create_step;
        let _realm_title = self.realm_title;
        let _realm_summary = self.realm_summary;
        let _realm_alias = self.realm_alias;
        let _realm_discoverability = self.realm_discoverability;
        let _realm_policy_join_rule = self.realm_policy_join_rule;
        let _realm_policy_history_access = self.realm_policy_history_access;
        let _realm_mls_activation = self.realm_mls_activation;
        let _realm_security_class = self.realm_security_class;
        let _realm_federation_policy = self.realm_federation_policy;
        let _realm_digest_algorithm = self.realm_digest_algorithm;
        let _realm_state = self.realm_state;
        let _realm_create_busy = self.realm_create_busy;
        let _created_realm_id = self.created_realm_id;
        let _pending_recovery_gate = self.pending_recovery_gate;
        let new_space_realm_id = self.new_space_realm_id;
        let new_space_title = self.new_space_title;
        let new_space_summary = self.new_space_summary;
        let new_space_kind = self.new_space_kind;
        let new_space_parent_id = self.new_space_parent_id;
        let _new_space_context_seen = self.new_space_context_seen;
        let new_space_state = self.new_space_state;
        let new_space_created_id = self.new_space_created_id;
        let principal_id = context
            .active_account
            .get_untracked()
            .map(|account| account.principal_id().to_string())
            .unwrap_or_default();
        let principal_id_for_create = principal_id.clone();
        let _principal_id_for_archive = principal_id.clone();
        let _principal_id_for_restore = principal_id.clone();
        let _principal_id_for_tombstone = principal_id;
        let status_strings = SpaceStatusStrings::resolve();
        let submit = {
            let base_url = base_url.clone();
            let strings = status_strings.clone();
            move |_| {
                let strings = strings.clone();
                let api_token = token.get();
                let base = base_url.clone();
                let realm_id = new_space_realm_id.get();
                let title = new_space_title.get();
                let summary = new_space_summary.get();
                let kind = new_space_kind.get();
                let parent_id = new_space_parent_id.get();
                let actor = principal_id_for_create.clone();
                new_space_state.revise(|value| {
                    *value = tr("setup.space.state.submitting_create");
                });
                {
                    let task_owner = context.clone();
                    let _ = task_owner.spawn(async move {
                                    match authed_api(&base, api_token).and_then(|api| api.event_submitter()) {
                                        Ok(submitter) => {
                                            let summary_opt = if summary.trim().is_empty() {
                                                None
                                            } else {
                                                Some(summary.as_str())
                                            };
                                            let parent_opt = if parent_id.trim().is_empty() {
                                                None
                                            } else {
                                                Some(parent_id.as_str())
                                            };
                                            match crate::transport::realm_write::create_space_under_realm(
                                                &submitter,
                                                &realm_id,
                                                &actor,
                                                &title,
                                                summary_opt,
                                                &kind,
                                                parent_opt,
                                            ).await {
                                                Ok(space) => {
                                                    // Persist a tagged Space projection so
                                                    // the sidebar (M-SIDEBAR-TIER-1) can
                                                    // classify it without re-fetching.
                                                    // `__kind` is inkson-local metadata —
                                                    // server-projected entries use the
                                                    // canonical `schema` field, but for the
                                                    // optimistic local write here we use the
                                                    // simpler marker.
                                                    let projection_body =
                                                        crate::realm_tree::OptimisticRealmTreeProjection::space(
                                                            crate::realm_tree::SpaceProjectionInput {
                                                                realm_id: realm_id.clone(),
                                                                kind: kind.clone(),
                                                                title: title.clone(),
                                                                summary: summary.clone(),
                                                                parent_space_id: parent_opt.map(str::to_owned),
                                                            },
                                                        )
                                                        .into_value();
                                                    state_store.write(|store| store.save_realm_tree_projection(
                                                        space.space_id.clone(),
                                                        projection_body,
                                                    ));
                                                    new_space_created_id.revise(|value|{*value=space.space_id.clone();});
                                                    new_space_state.revise(|value|{*value=SpaceStatusStrings::fill(
                                                        &strings.created,
                                                        &[
                                                            ("id", space.space_id.clone()),
                                                            ("kind", kind.clone()),
                                                            ("realm", realm_id.clone()),
                                                            (
                                                                "parent",
                                                                parent_opt
                                                                    .map(|p| format!(" under {p}"))
                                                                    .unwrap_or_default(),
                                                            ),
                                                        ],
                                                    );});
                                                }
                                                Err(error) => {
                                                    new_space_state.revise(|value|{*value=SpaceStatusStrings::fill(
                                                        &strings.create_failed,
                                                        &[("error", error.to_string())],
                                                    );});
                                                }
                                            }
                                        }
                                        Err(error) => {
                                            new_space_state.revise(|value|{*value=SpaceStatusStrings::fill(
                                                &strings.invalid_base_url,
                                                &[("error", error.to_string())],
                                            );});
                                        }
                                    }
                                });
                };
            }
        };
        submit(());
    }
    pub(super) fn archive_space(self, context: Rc<InksonContext>) {
        let token = context.token;
        let _active_account = context.active_account;
        let _selected_realm_id = context.selected_realm_id;
        let _account_recovery_configured = context.account_recovery_configured;
        let _realm_tree_nodes = context.realm_tree_nodes;
        let _new_space_context_node = context.new_space_context_node;
        let _state_store = context.state_store.clone();
        let base_url = context.base_url.get_untracked();
        let _plaintext_service_id = context
            .server_description
            .get_untracked()
            .as_ref()
            .map(|description| description.service_id.as_str().to_owned())
            .unwrap_or_default();
        let _create_step = self.create_step;
        let _realm_title = self.realm_title;
        let _realm_summary = self.realm_summary;
        let _realm_alias = self.realm_alias;
        let _realm_discoverability = self.realm_discoverability;
        let _realm_policy_join_rule = self.realm_policy_join_rule;
        let _realm_policy_history_access = self.realm_policy_history_access;
        let _realm_mls_activation = self.realm_mls_activation;
        let _realm_security_class = self.realm_security_class;
        let _realm_federation_policy = self.realm_federation_policy;
        let _realm_digest_algorithm = self.realm_digest_algorithm;
        let _realm_state = self.realm_state;
        let _realm_create_busy = self.realm_create_busy;
        let _created_realm_id = self.created_realm_id;
        let _pending_recovery_gate = self.pending_recovery_gate;
        let new_space_realm_id = self.new_space_realm_id;
        let _new_space_title = self.new_space_title;
        let _new_space_summary = self.new_space_summary;
        let _new_space_kind = self.new_space_kind;
        let _new_space_parent_id = self.new_space_parent_id;
        let _new_space_context_seen = self.new_space_context_seen;
        let new_space_state = self.new_space_state;
        let new_space_created_id = self.new_space_created_id;
        let principal_id = context
            .active_account
            .get_untracked()
            .map(|account| account.principal_id().to_string())
            .unwrap_or_default();
        let _principal_id_for_create = principal_id.clone();
        let principal_id_for_archive = principal_id.clone();
        let _principal_id_for_restore = principal_id.clone();
        let _principal_id_for_tombstone = principal_id;
        let status_strings = SpaceStatusStrings::resolve();
        let submit = {
            let base = base_url.clone();
            let strings = status_strings.clone();
            move |_| {
                let strings = strings.clone();
                let api_token = token.get();
                let base = base.clone();
                let actor = principal_id_for_archive.clone();
                let space_id = new_space_created_id.get();
                let realm_id = new_space_realm_id.get();
                new_space_state.revise(|value| {
                    *value = tr("setup.space.state.submitting_archive");
                });
                {
                    let task_owner = context.clone();
                    let _ = task_owner.spawn(async move {
                        match authed_api(&base, api_token).and_then(|api| api.event_submitter()) {
                            Ok(submitter) => {
                                match crate::transport::realm_write::change_space_lifecycle(
                                    &submitter,
                                    &space_id,
                                    &realm_id,
                                    &actor,
                                    EventKind::SpaceArchive,
                                )
                                .await
                                {
                                    Ok(()) => new_space_state.revise(|value| {
                                        *value = SpaceStatusStrings::fill(
                                            &strings.archived,
                                            &[("id", short_protocol_id(&space_id))],
                                        );
                                    }),
                                    Err(error) => new_space_state.revise(|value| {
                                        *value = SpaceStatusStrings::fill(
                                            &strings.archive_failed,
                                            &[("error", error.to_string())],
                                        );
                                    }),
                                }
                            }
                            Err(error) => new_space_state.revise(|value| {
                                *value = SpaceStatusStrings::fill(
                                    &strings.invalid_base_url,
                                    &[("error", error.to_string())],
                                );
                            }),
                        }
                    });
                };
            }
        };
        submit(());
    }
    pub(super) fn restore_space(self, context: Rc<InksonContext>) {
        let token = context.token;
        let _active_account = context.active_account;
        let _selected_realm_id = context.selected_realm_id;
        let _account_recovery_configured = context.account_recovery_configured;
        let _realm_tree_nodes = context.realm_tree_nodes;
        let _new_space_context_node = context.new_space_context_node;
        let _state_store = context.state_store.clone();
        let base_url = context.base_url.get_untracked();
        let _plaintext_service_id = context
            .server_description
            .get_untracked()
            .as_ref()
            .map(|description| description.service_id.as_str().to_owned())
            .unwrap_or_default();
        let _create_step = self.create_step;
        let _realm_title = self.realm_title;
        let _realm_summary = self.realm_summary;
        let _realm_alias = self.realm_alias;
        let _realm_discoverability = self.realm_discoverability;
        let _realm_policy_join_rule = self.realm_policy_join_rule;
        let _realm_policy_history_access = self.realm_policy_history_access;
        let _realm_mls_activation = self.realm_mls_activation;
        let _realm_security_class = self.realm_security_class;
        let _realm_federation_policy = self.realm_federation_policy;
        let _realm_digest_algorithm = self.realm_digest_algorithm;
        let _realm_state = self.realm_state;
        let _realm_create_busy = self.realm_create_busy;
        let _created_realm_id = self.created_realm_id;
        let _pending_recovery_gate = self.pending_recovery_gate;
        let new_space_realm_id = self.new_space_realm_id;
        let _new_space_title = self.new_space_title;
        let _new_space_summary = self.new_space_summary;
        let _new_space_kind = self.new_space_kind;
        let _new_space_parent_id = self.new_space_parent_id;
        let _new_space_context_seen = self.new_space_context_seen;
        let new_space_state = self.new_space_state;
        let new_space_created_id = self.new_space_created_id;
        let principal_id = context
            .active_account
            .get_untracked()
            .map(|account| account.principal_id().to_string())
            .unwrap_or_default();
        let _principal_id_for_create = principal_id.clone();
        let _principal_id_for_archive = principal_id.clone();
        let principal_id_for_restore = principal_id.clone();
        let _principal_id_for_tombstone = principal_id;
        let status_strings = SpaceStatusStrings::resolve();
        let submit = {
            let base = base_url.clone();
            let strings = status_strings.clone();
            move |_| {
                let strings = strings.clone();
                let api_token = token.get();
                let base = base.clone();
                let actor = principal_id_for_restore.clone();
                let space_id = new_space_created_id.get();
                let realm_id = new_space_realm_id.get();
                new_space_state.revise(|value| {
                    *value = tr("setup.space.state.submitting_restore");
                });
                {
                    let task_owner = context.clone();
                    let _ = task_owner.spawn(async move {
                        match authed_api(&base, api_token).and_then(|api| api.event_submitter()) {
                            Ok(submitter) => {
                                match crate::transport::realm_write::change_space_lifecycle(
                                    &submitter,
                                    &space_id,
                                    &realm_id,
                                    &actor,
                                    EventKind::SpaceRestore,
                                )
                                .await
                                {
                                    Ok(()) => new_space_state.revise(|value| {
                                        *value = SpaceStatusStrings::fill(
                                            &strings.restored,
                                            &[("id", short_protocol_id(&space_id))],
                                        );
                                    }),
                                    Err(error) => new_space_state.revise(|value| {
                                        *value = SpaceStatusStrings::fill(
                                            &strings.restore_failed,
                                            &[("error", error.to_string())],
                                        );
                                    }),
                                }
                            }
                            Err(error) => new_space_state.revise(|value| {
                                *value = SpaceStatusStrings::fill(
                                    &strings.invalid_base_url,
                                    &[("error", error.to_string())],
                                );
                            }),
                        }
                    });
                };
            }
        };
        submit(());
    }
    pub(super) fn tombstone_space(self, context: Rc<InksonContext>) {
        let token = context.token;
        let _active_account = context.active_account;
        let _selected_realm_id = context.selected_realm_id;
        let _account_recovery_configured = context.account_recovery_configured;
        let _realm_tree_nodes = context.realm_tree_nodes;
        let _new_space_context_node = context.new_space_context_node;
        let _state_store = context.state_store.clone();
        let base_url = context.base_url.get_untracked();
        let _plaintext_service_id = context
            .server_description
            .get_untracked()
            .as_ref()
            .map(|description| description.service_id.as_str().to_owned())
            .unwrap_or_default();
        let _create_step = self.create_step;
        let _realm_title = self.realm_title;
        let _realm_summary = self.realm_summary;
        let _realm_alias = self.realm_alias;
        let _realm_discoverability = self.realm_discoverability;
        let _realm_policy_join_rule = self.realm_policy_join_rule;
        let _realm_policy_history_access = self.realm_policy_history_access;
        let _realm_mls_activation = self.realm_mls_activation;
        let _realm_security_class = self.realm_security_class;
        let _realm_federation_policy = self.realm_federation_policy;
        let _realm_digest_algorithm = self.realm_digest_algorithm;
        let _realm_state = self.realm_state;
        let _realm_create_busy = self.realm_create_busy;
        let _created_realm_id = self.created_realm_id;
        let _pending_recovery_gate = self.pending_recovery_gate;
        let new_space_realm_id = self.new_space_realm_id;
        let _new_space_title = self.new_space_title;
        let _new_space_summary = self.new_space_summary;
        let _new_space_kind = self.new_space_kind;
        let _new_space_parent_id = self.new_space_parent_id;
        let _new_space_context_seen = self.new_space_context_seen;
        let new_space_state = self.new_space_state;
        let new_space_created_id = self.new_space_created_id;
        let principal_id = context
            .active_account
            .get_untracked()
            .map(|account| account.principal_id().to_string())
            .unwrap_or_default();
        let _principal_id_for_create = principal_id.clone();
        let _principal_id_for_archive = principal_id.clone();
        let _principal_id_for_restore = principal_id.clone();
        let principal_id_for_tombstone = principal_id;
        let status_strings = SpaceStatusStrings::resolve();
        let submit = {
            let base = base_url.clone();
            let strings = status_strings.clone();
            move |_| {
                let strings = strings.clone();
                let api_token = token.get();
                let base = base.clone();
                let actor = principal_id_for_tombstone.clone();
                let space_id = new_space_created_id.get();
                let realm_id = new_space_realm_id.get();
                new_space_state.revise(|value| {
                    *value = tr("setup.space.state.submitting_tombstone");
                });
                {
                    let task_owner = context.clone();
                    let _ = task_owner.spawn(async move {
                        match authed_api(&base, api_token).and_then(|api| api.event_submitter()) {
                            Ok(submitter) => {
                                match crate::transport::realm_write::change_space_lifecycle(
                                    &submitter,
                                    &space_id,
                                    &realm_id,
                                    &actor,
                                    EventKind::SpaceTombstone,
                                )
                                .await
                                {
                                    Ok(()) => new_space_state.revise(|value| {
                                        *value = SpaceStatusStrings::fill(
                                            &strings.tombstoned,
                                            &[("id", short_protocol_id(&space_id))],
                                        );
                                    }),
                                    Err(error) => new_space_state.revise(|value| {
                                        *value = SpaceStatusStrings::fill(
                                            &strings.tombstone_failed,
                                            &[("error", error.to_string())],
                                        );
                                    }),
                                }
                            }
                            Err(error) => new_space_state.revise(|value| {
                                *value = SpaceStatusStrings::fill(
                                    &strings.invalid_base_url,
                                    &[("error", error.to_string())],
                                );
                            }),
                        }
                    });
                };
            }
        };
        submit(());
    }
}
pub(super) fn page(scope: &Scope, context: Rc<InksonContext>, draft: super::SetupDraft) -> View {
    {
        let ctx = context.clone();
        scope.effect(move || {
            let context_node = ctx.new_space_context_node.get();
            let selected = ctx.selected_realm_id.get();
            let nodes = ctx.realm_tree_nodes.get();
            let key = if context_node.is_empty() {
                selected.clone()
            } else {
                context_node
            };
            if key.is_empty() || draft.new_space_context_seen.get_untracked() == key {
                return;
            }
            let target = nodes
                .iter()
                .find(|node| node.id == key)
                .map(|node| match node.kind {
                    RealmTreeNodeKind::Realm => (node.id.clone(), String::new()),
                    RealmTreeNodeKind::Space => {
                        (node.projection_realm_id().to_owned(), node.id.clone())
                    }
                })
                .or_else(|| {
                    ctx.state_store.read(|store| {
                        store.load().realm_tree_projections.get(&key).map(|body| {
                            let is_space = body
                                .get("__kind")
                                .and_then(Value::as_str)
                                .or_else(|| body.get("schema").and_then(Value::as_str))
                                .is_some_and(|kind| kind == "space" || kind == SchemaId::SPACE_V1);
                            if is_space {
                                (
                                    body.get("realm_id")
                                        .and_then(Value::as_str)
                                        .unwrap_or(&selected)
                                        .to_owned(),
                                    key.clone(),
                                )
                            } else {
                                (key.clone(), String::new())
                            }
                        })
                    })
                })
                .or_else(|| {
                    if key.starts_with("ak:realm:") {
                        Some((key.clone(), String::new()))
                    } else if key.starts_with("ak:space:") && !selected.is_empty() {
                        Some((selected, key.clone()))
                    } else {
                        None
                    }
                });
            if let Some((realm, parent)) = target {
                draft.new_space_context_seen.revise(|v| *v = key);
                draft.new_space_realm_id.revise(|v| *v = realm);
                draft.new_space_parent_id.revise(|v| *v = parent);
                draft.new_space_created_id.revise(|v| v.clear());
                draft
                    .new_space_state
                    .revise(|v| *v = tr("setup.state.draft"));
            }
        });
    }
    let parents = {
        let ctx = context.clone();
        reactive(
            scope.bond(move || {
                let _ = ctx.state_revision.get();
                draft.new_space_realm_id.get()
            }),
            {
                let ctx = context.clone();
                move |scope, realm| {
                    let mut options = vec![(String::new(), tr("setup.space.parent.root"))];
                    options.extend(ctx.state_store.read(|store| {
                        store
                            .load()
                            .realm_tree_projections
                            .into_iter()
                            .filter(|(_, body)| {
                                let kind = body
                                    .get("__kind")
                                    .and_then(Value::as_str)
                                    .or_else(|| body.get("schema").and_then(Value::as_str));
                                matches!(kind, Some("space") | Some(SchemaId::SPACE_V1))
                                    && body.get("realm_id").and_then(Value::as_str)
                                        == Some(realm.as_str())
                            })
                            .map(|(id, body)| {
                                let title = crate::realm_tree::projection_title(&id, &body);
                                (id, title)
                            })
                            .collect::<Vec<_>>()
                    }));
                    choice(
                        scope,
                        ctx.clone(),
                        "new-space-parent-input",
                        "setup.space.field.parent",
                        draft.new_space_parent_id,
                        options,
                        !realm.is_empty(),
                        move |next| draft.new_space_parent_id.revise(|v| *v = next),
                    )
                }
            },
        )
    };
    let enabled = {
        let ctx = context.clone();
        scope.bond(move || {
            !ctx.token.get().is_empty()
                && !draft.new_space_realm_id.get().is_empty()
                && !draft.new_space_title.get().trim().is_empty()
        })
    };
    let submit = action(
        scope,
        context.clone(),
        "new-space-submit-button",
        "setup.space.action.create",
        "primary",
        enabled,
        {
            let ctx = context.clone();
            move || draft.create_space(ctx.clone())
        },
    );
    let form = stack(
        "event",
        vec![
            stack(
                "workflow-form setup-form-grid",
                vec![
                    input(
                        scope,
                        context.clone(),
                        "new-space-title-input",
                        "setup.space.field.title",
                        draft.new_space_title,
                        true,
                    ),
                    choice(
                        scope,
                        context.clone(),
                        "new-space-kind-input",
                        "setup.space.field.kind",
                        draft.new_space_kind,
                        SPACE_KIND_OPTIONS
                            .iter()
                            .map(|(wire, label, _)| (wire.to_string(), tr(label)))
                            .collect(),
                        true,
                        move |next| draft.new_space_kind.revise(|v| *v = next),
                    ),
                    field(
                        scope,
                        context.clone(),
                        "new-space-summary-input",
                        "setup.field.summary",
                        draft.new_space_summary,
                        true,
                        true,
                        move |next| draft.new_space_summary.revise(|v| *v = next),
                    ),
                    parents,
                ],
            ),
            line("actions", vec![submit]),
        ],
    );
    let outcome = stack(
        "event",
        vec![
            line(
                "event-head",
                vec![
                    plain(context.translated(scope, "setup.space.outcome")),
                    paragraph(
                        "muted",
                        context.translated(scope, "setup.space.outcome.hint"),
                    ),
                ],
            ),
            line(
                "setup-summary-row",
                vec![
                    plain(context.translated(scope, "setup.space.created")),
                    paragraph(
                        "mono new-space-created-id",
                        scope.bond(move || {
                            let id = draft.new_space_created_id.get();
                            if id.is_empty() {
                                tr("setup.space.not_created")
                            } else {
                                short_protocol_id(&id)
                            }
                        }),
                    ),
                ],
            ),
            line(
                "setup-summary-row setup-summary-row-stack",
                vec![
                    plain(context.translated(scope, "setup.space.status")),
                    paragraph("muted", draft.new_space_state),
                ],
            ),
            line(
                "setup-summary-row setup-summary-row-stack",
                vec![
                    plain(context.translated(scope, "setup.space.wire_shape")),
                    paragraph(
                        "muted",
                        context.translated(scope, "setup.space.wire_shape.body"),
                    ),
                ],
            ),
        ],
    );
    let ctx = context.clone();
    let lifecycle = reactive(draft.new_space_created_id, move |scope, id| {
        let mut children = vec![line(
            "event-head",
            vec![
                plain(ctx.translated(scope, "setup.space.lifecycle")),
                paragraph("muted", ctx.translated(scope, "setup.space.lifecycle.hint")),
            ],
        )];
        if id.is_empty() {
            children.push(paragraph(
                "muted",
                ctx.translated(scope, "setup.space.lifecycle.empty"),
            ));
        } else {
            let mut buttons = vec![];
            for (key, label, operation) in [
                ("space-lifecycle-archive", "setup.space.action.archive", 0),
                ("space-lifecycle-restore", "setup.space.action.restore", 1),
                (
                    "space-lifecycle-tombstone",
                    "setup.space.action.tombstone",
                    2,
                ),
            ] {
                let ctx = ctx.clone();
                buttons.push(action(
                    scope,
                    ctx.clone(),
                    key,
                    label,
                    if operation == 2 {
                        "destructive"
                    } else {
                        "secondary"
                    },
                    true,
                    move || match operation {
                        0 => draft.archive_space(ctx.clone()),
                        1 => draft.restore_space(ctx.clone()),
                        _ => draft.tombstone_space(ctx.clone()),
                    },
                ));
            }
            children.push(line("actions", buttons));
            children.push(paragraph(
                "muted",
                ctx.translated(scope, "setup.space.tombstone_warning"),
            ));
        }
        stack("event space-lifecycle-panel", children)
    });
    stack(
        "setup-shell new-space-shell space-create-strand",
        vec![
            stack("setup-column", vec![form]),
            stack("setup-column", vec![outcome, lifecycle]),
        ],
    )
}
