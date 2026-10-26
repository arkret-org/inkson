//! Protected E2EE cache occupancy, browser quota, and explicit cleanup controls.

use std::rc::Rc;

use glory::prelude::*;

use super::widgets::*;
use crate::presentation::{InksonContext, View};
use crate::state::{BrowserStorageEstimate, E2eePlaintextCacheClearScope};
use crate::views::helpers::short_protocol_id;

// Keep the message identity until render so completed operations follow locale changes.
#[derive(Clone, Default)]
enum StorageFeedback {
    #[default]
    Empty,
    Message(&'static str),
    Error(&'static str, String),
}

impl StorageFeedback {
    fn text(&self) -> String {
        match self {
            Self::Empty => String::new(),
            Self::Message(key) => crate::i18n::tr(key),
            Self::Error(key, detail) => crate::i18n::tr_args(key, &[("detail", detail.clone())]),
        }
    }
}

fn format_storage_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * KIB;
    const GIB: f64 = 1024.0 * MIB;
    let bytes = bytes as f64;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{} B", bytes as u64)
    }
}

fn browser_storage_summary(estimate: BrowserStorageEstimate) -> String {
    let percent = estimate
        .usage_ratio()
        .map(|ratio| format!(" ({:.0}%)", ratio * 100.0))
        .unwrap_or_default();
    crate::i18n::tr_args(
        "settings.storage.quota_summary",
        &[
            ("used", format_storage_bytes(estimate.usage_bytes)),
            ("quota", format_storage_bytes(estimate.quota_bytes)),
            ("percent", percent),
        ],
    )
}

fn clear_target_text(scope: &E2eePlaintextCacheClearScope) -> String {
    match scope {
        E2eePlaintextCacheClearScope::All => crate::i18n::tr("settings.storage.target_all"),
        E2eePlaintextCacheClearScope::Realm(realm_id) => crate::i18n::tr_args(
            "settings.storage.target_realm",
            &[("realm", short_protocol_id(realm_id))],
        ),
    }
}

fn metric(label: View, value: View) -> View {
    stack("metric", vec![label, value])
}

fn metric_label(value: impl Into<Lotus<String>>) -> View {
    Box::new(text().class("storage-metric-label").content(value))
}

fn warning(scope: &Scope, context: Rc<InksonContext>, title: &str, body: &str) -> View {
    stack(
        "callout warn",
        vec![stack(
            "body",
            vec![
                Box::new(
                    text()
                        .class("storage-warning-title")
                        .content(context.translated(scope, title)),
                ),
                stack(
                    "storage-warning-copy",
                    vec![plain(context.translated(scope, body))],
                ),
            ],
        )],
    )
}

pub(super) fn settings(scope: &Scope, context: Rc<InksonContext>) -> View {
    stack(
        "settings-card-grid storage-settings-grid",
        vec![
            local_stores(scope, context.clone()),
            page(scope, context.clone()),
            diagnostics(scope, context),
        ],
    )
}

pub(super) fn local_stores(scope: &Scope, context: Rc<InksonContext>) -> View {
    let config_store = context.config_store;
    let locale = context.locale;
    let config_bytes = scope.bond(move || {
        let _ = locale.get();
        let bytes = config_store
            .get()
            .load()
            .server_url()
            .map(|url| url.as_str().len())
            .unwrap_or(0);
        crate::i18n::tr_args(
            "settings.local_stores.approx_bytes",
            &[("bytes", bytes.to_string())],
        )
    });
    let translated = |key| context.translated(scope, key);
    stack(
        "event storage-table",
        vec![
            line(
                "event-head",
                vec![
                    plain(translated("settings.local_stores.title")),
                    plain(translated("settings.local_stores.badge")),
                ],
            ),
            stack(
                "metric-grid",
                vec![
                    metric(
                        metric_label(translated("settings.local_stores.config_store")),
                        plain(translated("settings.local_stores.active")),
                    ),
                    metric(
                        metric_label(translated("settings.local_stores.config_size")),
                        plain(config_bytes),
                    ),
                    metric(
                        metric_label(translated("settings.local_stores.state_store")),
                        plain(translated("settings.local_stores.active")),
                    ),
                    metric(
                        metric_label(translated("settings.local_stores.platform")),
                        plain(translated(if cfg!(target_arch = "wasm32") {
                            "settings.local_stores.platform_web"
                        } else {
                            "settings.local_stores.platform_native"
                        })),
                    ),
                ],
            ),
        ],
    )
}

pub(super) fn diagnostics(scope: &Scope, context: Rc<InksonContext>) -> View {
    let label = context.translated(scope, "settings.storage_risks.title");
    let advanced = context.translated(scope, "settings.group.advanced");
    let content_context = context.clone();
    Box::new(
        sapid::collapsible("storage-risks")
            .unstyled()
            .class("event storage-risks")
            .label(label)
            .default_open(false)
            .trigger_content(move || {
                Box::new(group().fill(vec![plain(label), plain(advanced)])) as View
            })
            .content(move || {
                let context = content_context.clone();
                widget(move |scope| {
                    let rows = if cfg!(target_arch = "wasm32") {
                        vec![
                            (
                                "bounded_projection",
                                "bounded_projection_hint",
                                "badge-info risk-badge",
                                "settings.storage_risks.badge_bounded",
                            ),
                            (
                                "protected_e2ee",
                                "protected_e2ee_hint",
                                "badge-success",
                                "manage.row_encrypted",
                            ),
                            (
                                "single_tab",
                                "single_tab_hint",
                                "badge-info",
                                "settings.storage_risks.badge_info",
                            ),
                        ]
                    } else {
                        vec![(
                            "filesystem",
                            "filesystem_hint",
                            "badge-success",
                            "settings.storage_risks.badge_ok",
                        )]
                    };
                    let rows = rows
                        .into_iter()
                        .map(|(title, hint, badge, value)| {
                            let label = line(
                                "storage-metric-label",
                                vec![
                                    plain(context.translated(
                                        scope,
                                        format!("settings.storage_risks.{title}"),
                                    )),
                                    crate::components::help_tip(
                                        scope,
                                        context.clone(),
                                        crate::components::HelpTipProps {
                                            text: crate::i18n::tr(&format!(
                                                "settings.storage_risks.{hint}"
                                            )),
                                        },
                                    ),
                                ],
                            );
                            metric(
                                label,
                                Box::new(
                                    text()
                                        .class(format!("badge {badge}"))
                                        .content(context.translated(scope, value)),
                                ),
                            )
                        })
                        .collect::<Vec<_>>();
                    group().fill(rows).build(scope)
                })
            }),
    )
}

async fn refresh_browser_storage_quota(
    quota: Cage<Option<BrowserStorageEstimate>>,
    status: Cage<StorageFeedback>,
) {
    quota.revise(|value| {
        *value = None;
    });
    status.revise(|value| {
        *value = StorageFeedback::Message("settings.storage.checking");
    });
    let result = crate::state::browser_storage_estimate().await;
    match result {
        Ok(Some(estimate)) => {
            quota.revise(|value| {
                *value = Some(estimate);
            });
            status.revise(|value| {
                *value = StorageFeedback::Empty;
            });
        }
        Ok(None) => status.revise(|value| {
            *value = StorageFeedback::Message("settings.storage.browser_only");
        }),
        Err(error) => status.revise(|value| {
            *value = StorageFeedback::Error("settings.storage.quota_error", error.to_string())
        }),
    }
}

pub(super) fn page(scope: &Scope, context: Rc<InksonContext>) -> View {
    let cache_usage = scope.cage(
        context
            .state_store
            .read(|store| store.e2ee_plaintext_cache_usage()),
    );
    let pending_clear = scope.cage(None::<E2eePlaintextCacheClearScope>);
    let cache_status = scope.cage(StorageFeedback::default());
    let browser_quota = scope.cage(None::<BrowserStorageEstimate>);
    let browser_quota_status = scope.cage(StorageFeedback::default());
    spawn(
        scope,
        refresh_browser_storage_quota(browser_quota, browser_quota_status),
    );
    let quota_context = context.clone();
    let quota = reactive(browser_quota, move |scope, estimate| {
        let context = quota_context.clone();
        let mut children = vec![line(
            "event-head",
            vec![
                plain(context.translated(scope, "settings.storage.quota_title")),
                Box::new(
                    text()
                        .class(if estimate.is_some_and(|value| value.is_near_quota()) {
                            "badge badge-warning browser-storage-quota-warning"
                        } else {
                            "badge badge-info"
                        })
                        .content(context.translated(
                            scope,
                            if estimate.is_some_and(|value| value.is_near_quota()) {
                                "settings.storage.low_space"
                            } else {
                                "settings.storage.origin_total"
                            },
                        )),
                ),
            ],
        )];
        if let Some(estimate) = estimate {
            children.push(metric(
                metric_label(context.translated(scope, "settings.storage.used_available")),
                plain(browser_storage_summary(estimate)),
            ));
            if estimate.is_near_quota() {
                children.push(warning(
                    scope,
                    context.clone(),
                    "settings.storage.quota_warning",
                    "settings.storage.quota_guidance",
                ));
            }
        } else {
            children.push(status(
                scope.bond(move || browser_quota_status.get().text()),
            ));
        }
        stack("event browser-storage-quota", children)
    });
    let usage_context = context.clone();
    let storage_owner = scope.downgrade();
    let usage = reactive(cache_usage, move |scope, usage| {
        let context = usage_context.clone();
        let mut children = vec![
            line(
                "event-head",
                vec![
                    plain(context.translated(scope, "settings.storage.cache_title")),
                    plain(context.translated(scope, "settings.storage.manual_only")),
                ],
            ),
            line(
                "metric-grid",
                vec![
                    metric(
                        metric_label(context.translated(scope, "settings.storage.plaintext")),
                        plain(format_storage_bytes(usage.plaintext_bytes as u64)),
                    ),
                    metric(
                        metric_label(context.translated(scope, "settings.storage.entries")),
                        plain(crate::i18n::tr_args(
                            "settings.storage.entry_summary",
                            &[
                                ("entries", usage.entry_count().to_string()),
                                ("realms", usage.realms.len().to_string()),
                            ],
                        )),
                    ),
                ],
            ),
            warning(
                scope,
                context.clone(),
                "settings.storage.eviction_disabled",
                "settings.storage.cache_warning",
            ),
        ];
        if usage.realms.is_empty() {
            children.push(paragraph(
                "muted",
                context.translated(scope, "settings.storage.empty"),
            ));
        }
        let mut rows = Vec::new();
        for (realm_id, realm_usage) in &usage.realms {
            let realm_id = realm_id.clone();
            let label = short_protocol_id(&realm_id);
            rows.push(stack(
                "metric",
                vec![
                    metric_label(label),
                    plain(crate::i18n::tr_args(
                        "settings.storage.realm_summary",
                        &[
                            (
                                "bytes",
                                format_storage_bytes(realm_usage.plaintext_bytes as u64),
                            ),
                            ("entries", realm_usage.entry_count().to_string()),
                            ("authored", realm_usage.authored_entries.to_string()),
                            ("received", realm_usage.received_entries.to_string()),
                        ],
                    )),
                    line(
                        "actions",
                        vec![action(
                            scope,
                            context.clone(),
                            "e2ee-cache-clear-realm",
                            "settings.storage.clear_realm",
                            "storage-action storage-action-sm storage-action-destructive",
                            true,
                            move || {
                                pending_clear.revise(|value| {
                                    *value =
                                        Some(E2eePlaintextCacheClearScope::Realm(realm_id.clone()))
                                })
                            },
                        )],
                    ),
                ],
            ));
        }
        if !rows.is_empty() {
            children.push(stack("metric-grid e2ee-cache-realm-usage", rows));
        }
        let weak = storage_owner.clone();
        let refresh_context = context.clone();
        children.push(line(
            "actions",
            vec![
                action(
                    scope,
                    context.clone(),
                    "e2ee-cache-refresh",
                    "common.refresh",
                    "storage-action storage-action-sm storage-action-secondary",
                    true,
                    move || {
                        cache_usage.revise(|value| {
                            *value = refresh_context
                                .state_store
                                .read(|store| store.e2ee_plaintext_cache_usage())
                        });
                        if let Some(scope) = weak.upgrade() {
                            spawn(
                                &scope,
                                refresh_browser_storage_quota(browser_quota, browser_quota_status),
                            );
                        }
                    },
                ),
                action(
                    scope,
                    context.clone(),
                    "e2ee-cache-clear-all",
                    "settings.storage.clear_all",
                    "storage-action storage-action-sm storage-action-destructive",
                    usage.entry_count() > 0,
                    move || {
                        pending_clear.revise(|value| {
                            *value = Some(E2eePlaintextCacheClearScope::All);
                        })
                    },
                ),
            ],
        ));
        children.push(status(scope.bond(move || cache_status.get().text())));
        stack("event e2ee-plaintext-cache", children)
    });
    let clear_context = context.clone();
    let confirmation = reactive(pending_clear, move |scope, pending| {
        let Some(clear_scope) = pending else {
            return empty();
        };
        let context = clear_context.clone();
        let clear_target = clear_target_text(&clear_scope);
        let weak = scope.downgrade();
        let write_context = context.clone();
        let title = crate::i18n::tr_args(
            "settings.storage.clear_title",
            &[("target", clear_target.clone())],
        );
        let body = stack(
            "modal-body",
            vec![
                paragraph(
                    "muted",
                    crate::i18n::tr_args(
                        "settings.storage.clear_body",
                        &[("target", clear_target)],
                    ),
                ),
                line(
                    "modal-foot actions",
                    vec![
                        action(
                            scope,
                            context.clone(),
                            "e2ee-cache-clear-cancel",
                            "common.cancel",
                            "storage-action storage-action-default storage-action-secondary",
                            true,
                            move || {
                                pending_clear.revise(|value| {
                                    *value = None;
                                })
                            },
                        ),
                        action(
                            scope,
                            context.clone(),
                            "e2ee-cache-clear-confirm",
                            "settings.storage.clear_confirm",
                            "storage-action storage-action-default storage-action-destructive",
                            true,
                            move || {
                                let Some(scope) = weak.upgrade() else { return };
                                let context = write_context.clone();
                                let clear_scope = clear_scope.clone();
                                spawn(&scope, async move {
                                    let secure_store =
                                        crate::secure_key_store::default_secure_key_store("inkson");
                                    let pending = context.state_store.write(|store| {
                                        store.prepare_e2ee_plaintext_cache_clear_with_secure_store(
                                            &clear_scope,
                                            secure_store.as_ref(),
                                        )
                                    });
                                    let result = match pending {
                                        Ok(Some(pending)) => {
                                            if let Err(error) =
                                                pending.persist(secure_store.as_ref()).await
                                            {
                                                context.state_store.write(|store| {
                                                    store.rollback_e2ee_plaintext_cache_clear(
                                                        pending,
                                                    )
                                                });
                                                Err(error)
                                            } else {
                                                Ok(Some(()))
                                            }
                                        }
                                        Ok(None) => Ok(None),
                                        Err(error) => Err(error),
                                    };
                                    let feedback = match result {
                                        Ok(Some(())) => {
                                            StorageFeedback::Message("settings.storage.cleared")
                                        }
                                        Ok(None) => {
                                            StorageFeedback::Message("settings.storage.no_match")
                                        }
                                        Err(error) => StorageFeedback::Error(
                                            "settings.storage.clear_error",
                                            error.to_string(),
                                        ),
                                    };
                                    cache_status.revise(|value| {
                                        *value = feedback;
                                    });
                                    cache_usage.revise(|value| {
                                        *value = context
                                            .state_store
                                            .read(|store| store.e2ee_plaintext_cache_usage())
                                    });
                                    pending_clear.revise(|value| {
                                        *value = None;
                                    });
                                });
                            },
                        ),
                    ],
                ),
            ],
        );
        super::widgets::confirmation(
            scope,
            context,
            "e2ee-cache-clear-modal",
            title,
            body,
            move || {
                pending_clear.revise(|value| {
                    *value = None;
                })
            },
        )
    });
    Box::new(group().fill(vec![quota, usage, confirmation]))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn storage_bytes_use_binary_units() {
        assert_eq!(format_storage_bytes(999), "999 B");
        assert_eq!(format_storage_bytes(1536), "1.5 KiB");
        assert_eq!(format_storage_bytes(2 * 1024 * 1024), "2.0 MiB");
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn production_storage_retains_four_grid_cards_metrics_and_a_real_diagnostic_disclosure() {
        use glory::render::{Event, NodeId, Props};
        let directory = tempfile::Builder::new()
            .prefix("storage-layout-")
            .tempdir()
            .unwrap();
        let executor = Rc::new(glory::core::executor::Executor::new(128));
        let app = App::with_host(executor.clone(), glory::render::memory::Memory::new);
        let account = crate::test_support::AccountFixture::new("ak:did_core:web:alice.example")
            .server_url("https://storage.example/")
            .build();
        let config = crate::config::ClientConfig {
            active_account: Some(account),
            ..Default::default()
        };
        let mut config_store =
            crate::config::LocalConfigStore::with_path(directory.path().join("config.json"));
        config_store.save(config.clone());
        let context = InksonContext::new(
            app.scope(),
            crate::presentation::BootState {
                config_store,
                config,
                state_store: crate::presentation::SharedStateStore::new(
                    crate::state::LocalStateStore::with_path(directory.path().join("state.json")),
                ),
                initial_credential: String::new(),
                realm_tree_nodes: vec![],
            },
            crate::routes::Route::SettingsSection {
                section: "storage".into(),
                filter: String::new(),
            },
            |_| Box::pin(std::future::pending()),
        );
        app.mount(settings(app.scope(), context.clone())).unwrap();
        for _ in 0..8 {
            executor.poll_one();
            app.flush().unwrap();
        }
        fn nodes(app: &App) -> Vec<NodeId> {
            let tree = app.tree();
            let mut pending = tree.roots().to_vec();
            let mut result = vec![];
            while let Some(id) = pending.pop() {
                result.push(id);
                pending.extend(tree.node(id).unwrap().children.iter().copied());
            }
            result
        }
        fn class(app: &App, class: &str) -> NodeId {
            nodes(app)
                .into_iter()
                .find(|id| {
                    app.tree()
                        .node(*id)
                        .unwrap()
                        .descriptor
                        .view()
                        .classes
                        .iter()
                        .any(|candidate| candidate == class)
                })
                .unwrap_or_else(|| panic!("missing Storage class {class}"))
        }
        fn boxed_children(app: &App, parent: NodeId) -> Vec<NodeId> {
            let tree = app.tree();
            let mut pending = tree
                .node(parent)
                .unwrap()
                .children
                .iter()
                .rev()
                .copied()
                .collect::<Vec<_>>();
            let mut result = vec![];
            while let Some(id) = pending.pop() {
                let node = tree.node(id).unwrap();
                if matches!(node.descriptor.view().props, Props::Group) {
                    pending.extend(node.children.iter().rev().copied());
                } else {
                    result.push(id);
                }
            }
            result
        }
        let grid = class(&app, "storage-settings-grid");
        let cards = boxed_children(&app, grid);
        assert_eq!(
            cards.len(),
            4,
            "quota/cache remain Fragment siblings of Local stores and diagnostics"
        );
        for (node, expected) in cards.into_iter().zip([
            "storage-table",
            "browser-storage-quota",
            "e2ee-plaintext-cache",
            "storage-risks",
        ]) {
            assert!(
                app.tree()
                    .node(node)
                    .unwrap()
                    .descriptor
                    .view()
                    .classes
                    .iter()
                    .any(|class| class == expected)
            );
        }
        let local = class(&app, "storage-table");
        let metrics = boxed_children(&app, local)
            .into_iter()
            .find(|id| {
                app.tree()
                    .node(*id)
                    .unwrap()
                    .descriptor
                    .view()
                    .classes
                    .iter()
                    .any(|class| class == "metric-grid")
            })
            .unwrap();
        assert_eq!(boxed_children(&app, metrics).len(), 4);
        assert!(nodes(&app).iter().any(|id| matches!(app.tree().node(*id).unwrap().descriptor.view().props, Props::Text(value) if value.content == crate::i18n::tr_args("settings.local_stores.approx_bytes", &[("bytes", "https://storage.example/".len().to_string())]))));
        class(&app, "warn");
        let clear = class(&app, "e2ee-cache-clear-all");
        assert!(
            matches!(app.tree().node(clear).unwrap().descriptor.view().props, Props::Button(button) if !button.enabled)
        );
        let refresh = class(&app, "e2ee-cache-refresh");
        assert!(
            app.tree()
                .node(refresh)
                .unwrap()
                .descriptor
                .view()
                .classes
                .iter()
                .any(|class| class == "storage-action-sm")
        );
        let diagnostics = class(&app, "storage-risks");
        let trigger = boxed_children(&app, diagnostics)
            .into_iter()
            .find(|id| {
                matches!(
                    app.tree().node(*id).unwrap().descriptor.view().props,
                    Props::Button(_)
                )
            })
            .unwrap();
        assert_eq!(
            app.tree()
                .node(trigger)
                .unwrap()
                .descriptor
                .view()
                .semantics
                .as_ref()
                .unwrap()
                .expanded,
            Some(false)
        );
        app.dispatch(trigger, Event::Activate).unwrap();
        app.flush().unwrap();
        assert_eq!(
            app.tree()
                .node(trigger)
                .unwrap()
                .descriptor
                .view()
                .semantics
                .as_ref()
                .unwrap()
                .expanded,
            Some(true)
        );
        assert!(nodes(&app).iter().any(|id| matches!(app.tree().node(*id).unwrap().descriptor.view().props, Props::Text(value) if value.content == context.tr("settings.storage_risks.filesystem"))));
        app.dispatch(trigger, Event::Activate).unwrap();
        app.flush().unwrap();
        assert_eq!(
            app.tree()
                .node(trigger)
                .unwrap()
                .descriptor
                .view()
                .semantics
                .as_ref()
                .unwrap()
                .expanded,
            Some(false)
        );
        assert!(
            app.tree().node(refresh).is_ok(),
            "diagnostic disclosure leaves cache controls mounted"
        );
    }
}
