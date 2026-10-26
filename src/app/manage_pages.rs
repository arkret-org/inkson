use super::*;

pub(super) fn contact_manage_scope_summary(contact: &crate::models::ContactView) -> String {
    let mut seen = BTreeSet::<String>::new();
    for scope in contact
        .bidirectional_scopes
        .iter()
        .chain(contact.effective_scopes.iter().flatten())
        .chain(contact.granted_to_peer_scopes.iter())
        .chain(contact.granted_by_peer_scopes.iter())
    {
        seen.insert(crate::models::contact_scope_wire(*scope).to_owned());
    }
    if seen.is_empty() {
        crate::i18n::tr("manage.contact_no_scopes")
    } else {
        seen.into_iter().collect::<Vec<_>>().join(", ")
    }
}

use std::rc::Rc;

use glory::prelude::*;

use super::session_shell::{action, block, nav};
use super::shell_state::ShellState;
use crate::presentation::widgets::*;
use crate::presentation::{InksonContext, View};

pub(super) fn realms_page(scope: &Scope, context: Rc<InksonContext>, ui: Rc<ShellState>) -> View {
    let source = scope.bond({
        let context = context.clone();
        let ui = ui.clone();
        move || {
            (
                context.realm_tree_nodes.get(),
                context.state_revision.get(),
                ui.realm_query.get(),
                context.locale.get(),
            )
        }
    });
    let rows = reactive(source, {
        let context = context.clone();
        let ui = ui.clone();
        move |scope, (nodes, _, query, _)| {
            let mut rows = Vec::new();
            let query = query.trim().to_ascii_lowercase();
            let _ = nodes;
            let data =
                super::sidebar::navigation_model(&context, &context.route.get_untracked(), "")
                    .manage_realm_rows;
            for row in data.iter().filter(|row| {
                sidebar_text_matches_query(&query, &[&row.realm_id, &row.title, &row.display_name])
            }) {
                let id = row.realm_id.clone();
                let label = &row.display_name;
                let encrypted = row.encrypted;
                let target = id.clone();
                let name = label.clone();
                let pending = ui.pending_leave;
                rows.push(block(
                    "realm-manage-row",
                    vec![
                        block(
                            "realm-manage-row-main",
                            vec![plain(label.clone()), paragraph("muted mono", id.clone())],
                        ),
                        block(
                            "realm-manage-row-meta",
                            vec![
                                paragraph(
                                    "pill muted xs",
                                    context.translated(
                                        scope,
                                        match encrypted {
                                            Some(true) => "manage.row_encrypted",
                                            Some(false) => "manage.row_unencrypted",
                                            None => "realm.security_unknown",
                                        },
                                    ),
                                ),
                                paragraph(
                                    "pill muted xs",
                                    crate::i18n::tr_args(
                                        "manage.row_spaces",
                                        &[("count", row.space_count.to_string())],
                                    ),
                                ),
                            ],
                        ),
                        block(
                            "realm-manage-row-actions",
                            vec![
                                nav(
                                    context.clone(),
                                    Route::Realm {
                                        realm_id: id.clone(),
                                    },
                                    "btn sm secondary",
                                    context.translated(scope, "setup.action.open_realm"),
                                    "",
                                ),
                                nav(
                                    context.clone(),
                                    Route::RealmAdmin { realm_id: id },
                                    "btn sm secondary",
                                    context.translated(scope, "realm.settings"),
                                    "",
                                ),
                                action(
                                    "btn sm danger",
                                    context.translated(scope, "realm_admin.leave_realm"),
                                    move || {
                                        pending.revise(|value| {
                                            *value = Some((target.clone(), name.clone()))
                                        })
                                    },
                                ),
                            ],
                        ),
                    ],
                ));
            }
            if rows.is_empty() {
                rows.push(block(
                    "members-empty",
                    vec![
                        paragraph(
                            "members-empty-title",
                            context.translated(
                                scope,
                                if data.is_empty() {
                                    "sidebar.realms_empty"
                                } else {
                                    "sidebar.realms_no_results"
                                },
                            ),
                        ),
                        paragraph(
                            "muted members-empty-hint",
                            context.translated(
                                scope,
                                if data.is_empty() {
                                    "manage.realms_empty_hint"
                                } else {
                                    "manage.no_results_hint"
                                },
                            ),
                        ),
                    ],
                ));
            }
            block("realm-manage-list", rows)
        }
    });
    block(
        "settings realm-manage-page",
        vec![block(
            "settings-shell realm-manage-shell",
            vec![block(
                "settings-content-stack realm-manage-main",
                vec![block(
                    "event realm-manage-list-card",
                    vec![
                        block(
                            "realm-manage-list-tools",
                            vec![
                                input_field(
                                    context.clone(),
                                    "manage-realms",
                                    context.translated(scope, "sidebar.search_realms"),
                                    ui.realm_query,
                                    Purpose::Text,
                                ),
                                nav(
                                    context.clone(),
                                    Route::PrincipalControl,
                                    "btn sm secondary realm-manage-pcr-link",
                                    context.translated(scope, "manage.principal_control_button"),
                                    "key",
                                ),
                            ],
                        ),
                        rows,
                    ],
                )],
            )],
        )],
    )
}
pub(super) fn principal_control_page(
    scope: &Scope,
    context: Rc<InksonContext>,
    realm_id: Option<String>,
) -> View {
    let mut children = vec![block(
        "compact-page-actions",
        vec![
            crate::components::help_tip(
                scope,
                context.clone(),
                crate::components::HelpTipProps {
                    text: context.tr("manage.principal_control_subtitle"),
                },
            ),
            nav(
                context.clone(),
                Route::RealmsManage,
                "btn sm secondary",
                context.translated(scope, "manage.back_to_realms"),
                "chevron-left",
            ),
        ],
    )];
    if let Some(id) = realm_id {
        children.extend([
            block(
                "principal-control-field",
                vec![
                    paragraph(
                        "muted",
                        context.translated(scope, "manage.principal_control_purpose_label"),
                    ),
                    plain(context.translated(scope, "manage.principal_control_purpose_value")),
                ],
            ),
            block(
                "principal-control-field",
                vec![
                    paragraph(
                        "muted",
                        context.translated(scope, "manage.principal_control_realm_id"),
                    ),
                    paragraph("mono", id),
                ],
            ),
            block(
                "panel-notice",
                vec![
                    crate::components::ui_icon("lock"),
                    plain(
                        context.translated(scope, "manage.principal_control_no_business_surfaces"),
                    ),
                ],
            ),
        ]);
    } else {
        children.push(paragraph(
            "members-empty-title",
            context.translated(scope, "manage.principal_control_unavailable"),
        ));
    }
    block(
        "settings realm-manage-page",
        vec![block(
            "settings-shell realm-manage-shell",
            vec![block(
                "settings-content-stack realm-manage-main",
                vec![block(
                    "event realm-manage-list-card principal-control-card",
                    children,
                )],
            )],
        )],
    )
}
pub(super) fn contacts_page(scope: &Scope, context: Rc<InksonContext>, ui: Rc<ShellState>) -> View {
    super::sidebar::load_direct_contacts_for_sidebar(
        scope,
        context.clone(),
        context.base_url.get_untracked(),
        context.token.get_untracked(),
        context.state_store.clone(),
        context.contact_rows,
        scope.cage(false),
    );
    let source = scope.bond({
        let context = context.clone();
        let ui = ui.clone();
        move || {
            (
                context.contact_rows.get(),
                ui.contact_query.get(),
                context.state_revision.get(),
                context.locale.get(),
            )
        }
    });
    let rows = reactive(source, {
        let context = context.clone();
        move |scope, (contacts, query, ..)| {
            let mut rows = Vec::new();
            let query = query.trim().to_ascii_lowercase();
            for contact in &contacts {
                let peer = crate::models::contact_peer_id(contact).to_string();
                let scopes = contact_manage_scope_summary(contact);
                let name = context
                    .state_store
                    .read(|store| crate::views::helpers::contact_peer_label(store, contact));
                let state = crate::models::contact_state_wire(contact.state);
                if !sidebar_text_matches_query(&query, &[&peer, &scopes, &name, state]) {
                    continue;
                }
                let direct = contact
                    .direct_conversation
                    .as_ref()
                    .map(|summary| {
                        crate::i18n::tr_args(
                            "manage.contact_dm",
                            &[(
                                "state",
                                crate::models::direct_conversation_binding_state_wire(
                                    summary.state,
                                )
                                .to_owned(),
                            )],
                        )
                    })
                    .unwrap_or_else(|| context.tr("manage.contact_no_dm"));
                let actor = contact.peer.contact_actor_id();
                let identity = match actor.as_account_id() {
                    Some(account) => format!(
                        "Principal: {} · Station: {}",
                        account.principal_id, account.station_id
                    ),
                    None => actor.to_string(),
                };
                use sha2::Digest;
                let identity_id = match glory::render::SemanticId::new(format!(
                    "managed-recipient-{}",
                    hex::encode(sha2::Sha256::digest(actor.to_string().as_bytes()))
                )) {
                    Ok(id) => id,
                    Err(error) => {
                        scope.report_error(error);
                        continue;
                    }
                };
                let described_by = identity_id.clone();
                rows.push(Box::new(
                    view()
                        .class("realm-manage-row contacts-manage-row")
                        .role(glory::render::Role::Group)
                        .name(name.clone())
                        .semantics(Some(Box::new(glory::render::Semantics {
                            described_by: Some(described_by),
                            ..Default::default()
                        })))
                        .fill(vec![
                            Box::new(
                                text()
                                    .class("sr-only contact-recipient-identity")
                                    .content(identity)
                                    .semantics(Some(Box::new(glory::render::Semantics {
                                        id: Some(identity_id),
                                        ..Default::default()
                                    }))),
                            ) as View,
                            block(
                                "realm-manage-row-main",
                                vec![plain(name), paragraph("muted", scopes)],
                            ),
                            block(
                                "realm-manage-row-meta",
                                vec![
                                    paragraph("pill muted xs", state),
                                    paragraph("pill muted xs", direct),
                                ],
                            ),
                        ]),
                ) as View);
            }
            if rows.is_empty() {
                rows.push(block(
                    "members-empty",
                    vec![
                        paragraph(
                            "members-empty-title",
                            context.translated(
                                scope,
                                if contacts.is_empty() {
                                    "contacts.empty"
                                } else {
                                    "manage.contacts_no_results"
                                },
                            ),
                        ),
                        paragraph(
                            "muted members-empty-hint",
                            context.translated(
                                scope,
                                if contacts.is_empty() {
                                    "manage.contacts_empty_hint"
                                } else {
                                    "manage.no_results_hint"
                                },
                            ),
                        ),
                    ],
                ));
            }
            block("realm-manage-list", rows)
        }
    });
    block(
        "settings realm-manage-page contacts-manage-page",
        vec![block(
            "settings-shell realm-manage-shell",
            vec![block(
                "settings-content-stack realm-manage-main",
                vec![block(
                    "event realm-manage-list-card",
                    vec![
                        block(
                            "realm-manage-list-tools",
                            vec![input_field(
                                context.clone(),
                                "manage-contacts",
                                context.translated(scope, "manage.search_contacts"),
                                ui.contact_query,
                                Purpose::Text,
                            )],
                        ),
                        rows,
                    ],
                )],
            )],
        )],
    )
}
pub(super) fn confirmations(scope: &Scope, context: Rc<InksonContext>, ui: Rc<ShellState>) -> View {
    let source = scope.bond({
        let ui = ui.clone();
        move || (ui.pending_leave.get(), ui.pending_delete.get())
    });
    reactive(source, move |scope, (leave, delete)| {
        let (realm, id, label) = match (leave, delete) {
            (Some((id, label)), _) => (true, id, label),
            (_, Some((id, label))) => (false, id, label),
            _ => return empty(),
        };
        let dismiss = ui.clone();
        let content_ctx = context.clone();
        let content_ui = ui.clone();
        crate::components::dismissible_popup(
            scope,
            context.clone(),
            crate::components::DismissiblePopupProps {
                overlay_class: "modal-backdrop".into(),
                surface_class: "modal danger-confirm-modal".into(),
                aria_label: context.tr(if realm {
                    "realm_admin.leave_confirm_title"
                } else {
                    "contacts.delete_confirm_title"
                }),
                overlay_test_id: None,
                surface_test_id: Some("sidebar-danger-confirm".into()),
                overlay_style: None,
                surface_style: None,
                on_dismiss: Rc::new(move |_| {
                    dismiss.pending_leave.revise(|value| *value = None);
                    dismiss.pending_delete.revise(|value| *value = None);
                }),
                children: Rc::new(move |scope| {
                    let weak = scope.downgrade();
                    let context = content_ctx.clone();
                    let ui = content_ui.clone();
                    let target = id.clone();
                    block(
                        "",
                        vec![
                            block(
                                "modal-head",
                                vec![heading(
                                    3,
                                    "",
                                    content_ctx.translated(
                                        scope,
                                        if realm {
                                            "realm_admin.leave_confirm_title"
                                        } else {
                                            "contacts.delete_confirm_title"
                                        },
                                    ),
                                )],
                            ),
                            block(
                                "modal-body workflow-form",
                                vec![
                                    paragraph(
                                        "callout danger",
                                        content_ctx.translated(
                                            scope,
                                            if realm {
                                                "realm_admin.leave_confirm_body"
                                            } else {
                                                "contacts.delete_confirm_body"
                                            },
                                        ),
                                    ),
                                    plain(label.clone()),
                                    paragraph("muted mono", id.clone()),
                                ],
                            ),
                            block(
                                "modal-foot",
                                vec![
                                    action(
                                        "btn secondary",
                                        content_ctx.translated(scope, "common.cancel"),
                                        {
                                            let ui = content_ui.clone();
                                            move || {
                                                ui.pending_leave.revise(|value| *value = None);
                                                ui.pending_delete.revise(|value| *value = None);
                                            }
                                        },
                                    ),
                                    action(
                                        "btn danger",
                                        content_ctx.translated(
                                            scope,
                                            if realm {
                                                "realm_admin.leave_confirm_button"
                                            } else {
                                                "contacts.delete"
                                            },
                                        ),
                                        move || {
                                            if let Some(scope) = weak.upgrade() {
                                                if realm {
                                                    leave_sidebar_realm(
                                                        &scope,
                                                        context.clone(),
                                                        context.base_url.get(),
                                                        context.token.get(),
                                                        target.clone(),
                                                        principal_id_owned(
                                                            context.principal_id.get(),
                                                        ),
                                                        context.state_store.clone(),
                                                        context.realm_tree_nodes,
                                                        context.selected_realm_id,
                                                        context.sync_cursor,
                                                    );
                                                } else {
                                                    delete_sidebar_contact(
                                                        &scope,
                                                        context.clone(),
                                                        context.base_url.get(),
                                                        context.token.get(),
                                                        target.clone(),
                                                        context.state_store.clone(),
                                                        context.contact_rows,
                                                        ui.contacts_loaded,
                                                    );
                                                }
                                                ui.pending_leave.revise(|value| *value = None);
                                                ui.pending_delete.revise(|value| *value = None);
                                            }
                                        },
                                    ),
                                ],
                            ),
                        ],
                    )
                }),
            },
        )
    })
}
