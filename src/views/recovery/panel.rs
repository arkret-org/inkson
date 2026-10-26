//! Custody-first recovery material enrollment and server ciphertext inventory.
use std::rc::Rc;

use glory::{Cage, Scope};

use super::backup_summary::{
    BackupInventoryStatus, backup_inventory_status, fmt_backup_timestamp, parse_backup_list,
    sorted_backups_latest_first,
};
use super::helpers::copy_recovery_text_to_clipboard;
use super::state::{fmt_relative, load_state, save_generated_recovery_key_metadata_in_store};
use super::types::BackupSummaryRow;
use super::upload::{RecoveryKeyBackupOutcome, upload_recovery_key_account_backup};
use crate::presentation::{InksonContext, View};
use crate::recovery_crypto::{
    RecoveryKeyConfirmationDiff, generate_recovery_key, recovery_key_confirmation_diff,
};
use crate::transport::auth::with_authed_api;
use crate::views::settings::widgets::*;
const RESTORE_BACKUP_TIME_LIMIT: usize = 5;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EnrollPhase {
    Idle,
    CustodyConfirmation,
    Publishing,
}
#[derive(Clone)]
struct RecoveryPage {
    context: Rc<InksonContext>,
    owner: glory::ui::WeakScope,
    live: Cage<String>,
    fingerprint: Cage<String>,
    rotated: Cage<String>,
    status: Cage<String>,
    confirmation: Cage<String>,
    phase: Cage<EnrollPhase>,
    attempts: Cage<u32>,
    copied: Cage<bool>,
    unauthorized: Cage<bool>,
    inventory_status: Cage<String>,
    inventory_busy: Cage<bool>,
    inventory_loaded: Cage<bool>,
    rows: Cage<Vec<BackupSummaryRow>>,
    cursor: Cage<Option<arkret_wire::Cursor>>,
}
impl RecoveryPage {
    fn material_established(&self) -> bool {
        !self.fingerprint.get().is_empty()
            || self
                .context
                .state_store
                .read(crate::components::mls_recovery_backup_configured)
    }
    fn generate(&self) {
        if self.phase.get_untracked() == EnrollPhase::Publishing
            || (self.material_established() && self.phase.get_untracked() == EnrollPhase::Idle)
        {
            return;
        }
        match generate_recovery_key() {
            Ok(key) => {
                self.live.revise(|value| *value = key);
                self.confirmation.revise(|value| value.clear());
                self.attempts.revise(|value| *value = 0);
                self.copied.revise(|value| *value = false);
                self.unauthorized.revise(|value| *value = false);
                self.phase
                    .revise(|value| *value = EnrollPhase::CustodyConfirmation);
                self.status
                    .revise(|value| *value = self.context.tr("recovery.panel.generated_status"));
            }
            Err(error) => self.status.revise(|value| {
                *value = crate::i18n::tr_args(
                    "recovery.panel.generate_failed",
                    &[("error", error.to_string())],
                )
            }),
        }
    }
    fn confirm(&self) {
        if self.phase.get_untracked() != EnrollPhase::CustodyConfirmation {
            return;
        }
        let key = self.live.get();
        if key.is_empty() {
            return;
        }
        match recovery_key_confirmation_diff(&key, &self.confirmation.get()) {
            RecoveryKeyConfirmationDiff::Match => {
                let Some(account) = self.context.active_account.get() else {
                    return;
                };
                self.phase.revise(|value| *value = EnrollPhase::Publishing);
                self.status
                    .revise(|value| *value = self.context.tr("recovery.panel.custody_confirmed"));
                let accepted_key = zeroize::Zeroizing::new(key.clone());
                let state = self.clone();
                let owner = self.owner.clone();
                let outcome = Rc::new(move |outcome| {
                    if owner.upgrade().is_none() {
                        return;
                    }
                    match outcome {
                        RecoveryKeyBackupOutcome::Established => {
                            let saved = state.context.state_store.write(|store| {
                                save_generated_recovery_key_metadata_in_store(store, &accepted_key)
                            });
                            let Some((fingerprint, rotated)) = saved else {
                                state
                                    .phase
                                    .revise(|value| *value = EnrollPhase::CustodyConfirmation);
                                state.status.revise(|value| {
                                    *value = state.context.tr("recovery.panel.metadata_save_failed")
                                });
                                return;
                            };
                            state.fingerprint.revise(|value| *value = fingerprint);
                            state.rotated.revise(|value| *value = rotated);
                            state.live.revise(|value| value.clear());
                            state.confirmation.revise(|value| value.clear());
                            state.attempts.revise(|value| *value = 0);
                            state.phase.revise(|value| *value = EnrollPhase::Idle);
                            state.status.revise(|value| {
                                *value = state.context.tr("recovery.panel.accepted_done")
                            });
                        }
                        RecoveryKeyBackupOutcome::DeviceUnauthorized => {
                            state
                                .phase
                                .revise(|value| *value = EnrollPhase::CustodyConfirmation);
                            state.unauthorized.revise(|value| *value = true);
                        }
                        RecoveryKeyBackupOutcome::Transient => state
                            .phase
                            .revise(|value| *value = EnrollPhase::CustodyConfirmation),
                    }
                });
                upload_recovery_key_account_backup(
                    self.context.clone(),
                    self.context.token,
                    self.context.device_id,
                    account,
                    self.context.state_store.handle(),
                    key,
                    self.status,
                    None,
                    Some(outcome),
                );
            }
            diff => {
                let attempts = self.attempts.get() + 1;
                self.attempts.revise(|value| *value = attempts);
                let extra = if attempts >= 3 {
                    self.context.tr("recovery.panel.retry_extra")
                } else {
                    String::new()
                };
                let message = match diff {
                    RecoveryKeyConfirmationDiff::WordCount { entered } => crate::i18n::tr_args(
                        "recovery.panel.word_count",
                        &[("entered", entered.to_string()), ("extra", extra)],
                    ),
                    RecoveryKeyConfirmationDiff::MismatchAt { index } => crate::i18n::tr_args(
                        "recovery.panel.word_mismatch",
                        &[("index", index.to_string()), ("extra", extra)],
                    ),
                    RecoveryKeyConfirmationDiff::Match => return,
                };
                self.status.revise(|value| *value = message);
            }
        }
    }
    fn inventory(&self) {
        if self.inventory_busy.get_untracked() {
            return;
        }
        let context = self.context.clone();
        let generation = context.session_generation.get();
        let session = context.active_account.get();
        let base = context.base_url.get();
        let token = context.token.get();
        let cursor = self.cursor.get();
        let state = self.clone();
        let Some(scope) = self.owner.upgrade() else {
            return;
        };
        self.inventory_busy.revise(|value| *value = true);
        self.inventory_status
            .revise(|value| *value = context.tr("recovery.panel.fetching"));
        spawn(&scope, async move {
            let result = with_authed_api(&base, token, |api| async move {
                api.list_key_backups_page(&arkret_sdk::KeyBackupsListQuery {
                    series_id: None,
                    backup_kind: None,
                    cursor,
                    limit: Some(50),
                })
                .await
            })
            .await;
            if !context.session_matches(generation, &session) {
                return;
            }
            match result {
                Ok(payload) => {
                    state
                        .cursor
                        .revise(|value| *value = payload.next_cursor.clone());
                    let rows =
                        parse_backup_list(&serde_json::to_value(&payload).unwrap_or_default());
                    let message = match backup_inventory_status(&rows) {
                        BackupInventoryStatus::Empty => {
                            context.tr("recovery.panel.inventory_empty")
                        }
                        BackupInventoryStatus::Loaded { count, latest } => crate::i18n::tr_args(
                            "recovery.panel.inventory_loaded",
                            &[("count", count.to_string()), ("latest", latest)],
                        ),
                    };
                    state.rows.revise(|value| *value = rows);
                    state.inventory_loaded.revise(|value| *value = true);
                    state.inventory_status.revise(|value| *value = message);
                }
                Err(error) => state.inventory_status.revise(|value| {
                    *value = crate::i18n::tr_args(
                        "recovery.panel.fetch_failed",
                        &[("error", error.display())],
                    )
                }),
            }
            state.inventory_busy.revise(|value| *value = false);
        });
    }
}
#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "panel_surface_tests.rs"]
mod surface_tests;

fn recovery_label(value: impl Into<glory::Lotus<String>>) -> View {
    use glory::prelude::*;
    Box::new(text().class("recovery-strong-label").content(value))
}

fn recovery_warning(
    scope: &Scope,
    context: Rc<InksonContext>,
    class: &str,
    title: &str,
    body: &str,
) -> View {
    stack(
        format!("callout warn {class}"),
        vec![stack(
            "body",
            vec![
                recovery_label(context.translated(scope, title)),
                plain(" "),
                plain(context.translated(scope, body)),
            ],
        )],
    )
}

fn recovery_fold(
    scope: &Scope,
    context: Rc<InksonContext>,
    key: &str,
    title: &str,
    subtitle: &str,
    help: Option<&str>,
    content: Vec<View>,
) -> View {
    use glory::prelude::*;
    let label = context.translated(scope, title);
    let subtitle = context.translated(scope, subtitle);
    let mut content = Some(content);
    let fold = Box::new(
        sapid::collapsible(key)
            .unstyled()
            .class("recovery-fold")
            .default_open(false)
            .label(label)
            .trigger_content(move || {
                Box::new(group().fill(vec![plain(label), plain(subtitle)])) as View
            })
            .content_policy(sapid::ContentPolicy::KeepMounted)
            .content(move || Box::new(group().fill(content.take().unwrap_or_default())) as View),
    ) as View;
    let mut children = vec![fold];
    if let Some(help) = help {
        children.push(stack(
            "recovery-fold-help",
            vec![crate::components::help_tip(
                scope,
                context.clone(),
                crate::components::HelpTipProps {
                    text: context.tr(help),
                },
            )],
        ));
    }
    stack(
        format!(
            "event recovery-fold-card {key}{}",
            if help.is_some() { " has-help" } else { "" }
        ),
        children,
    )
}

pub fn page(scope: &Scope, context: Rc<InksonContext>, _route: crate::routes::Route) -> View {
    let initial = load_state(&context.state_store);
    let state = RecoveryPage {
        context: context.clone(),
        owner: scope.downgrade(),
        live: scope.cage(String::new()),
        fingerprint: scope.cage(initial.recovery_key_fingerprint),
        rotated: scope.cage(initial.recovery_key_rotated_at),
        status: scope.cage(String::new()),
        confirmation: scope.cage(String::new()),
        phase: scope.cage(EnrollPhase::Idle),
        attempts: scope.cage(0),
        copied: scope.cage(false),
        unauthorized: scope.cage(false),
        inventory_status: scope.cage(String::new()),
        inventory_busy: scope.cage(false),
        inventory_loaded: scope.cage(false),
        rows: scope.cage(Vec::new()),
        cursor: scope.cage(None),
    };
    {
        let state = state.clone();
        let seen = scope.cage((
            context.session_generation.get_untracked(),
            context
                .active_account
                .get_untracked()
                .map(|account| (account.authority, account.device_id)),
        ));
        let context = context.clone();
        scope.effect(move || {
            let next = (
                context.session_generation.get(),
                context
                    .active_account
                    .get()
                    .map(|account| (account.authority, account.device_id)),
            );
            if seen.get_untracked() != next {
                seen.revise(|value| *value = next);
                use zeroize::Zeroize;
                state.live.revise(Zeroize::zeroize);
                state.confirmation.revise(Zeroize::zeroize);
                state.phase.revise(|value| *value = EnrollPhase::Idle);
                state.attempts.revise(|value| *value = 0);
                state.status.revise(String::clear);
                state.rows.revise(Vec::clear);
                state.cursor.revise(|value| *value = None);
                state.inventory_busy.revise(|value| *value = false);
                state.inventory_loaded.revise(|value| *value = false);
            }
        });
    }
    {
        let live = state.live;
        let confirmation = state.confirmation;
        let _ = scope.on_cleanup(move || {
            use zeroize::Zeroize;
            let _ = live.try_revise(Zeroize::zeroize);
            let _ = confirmation.try_revise(Zeroize::zeroize);
        });
    }
    let live = state.live;
    let phase = state.phase;
    let fingerprint = state.fingerprint;
    let rotated = state.rotated;
    let confirmed = state.confirmation;
    let revision = context.state_revision;
    let sync = state.clone();
    scope.effect(move || {
        let _ = revision.get();
        let next = load_state(&sync.context.state_store);
        sync.fingerprint
            .revise(|value| *value = next.recovery_key_fingerprint);
        sync.rotated
            .revise(|value| *value = next.recovery_key_rotated_at);
    });
    let backup_context = context.clone();
    let backed_up = scope.bond(move || {
        let _ = backup_context.state_revision.get();
        backup_context
            .state_store
            .read(crate::components::mls_recovery_backup_configured)
    });
    let hero_context = context.clone();
    let hero = reactive(
        scope.bond(move || (live.get(), phase.get(), fingerprint.get())),
        move |scope, (key, phase, fingerprint)| {
            let context = hero_context.clone();
            if phase == EnrollPhase::Publishing {
                return stack(
                    "recovery-key-empty recovery-key-pending",
                    vec![
                        recovery_label(
                            context.translated(scope, "recovery.panel.publishing_title"),
                        ),
                        paragraph(
                            "muted",
                            context.translated(scope, "recovery.panel.publishing_hint"),
                        ),
                    ],
                );
            }
            if !key.is_empty() {
                let words = key
                    .split_whitespace()
                    .map(|word| paragraph("rk-word", format!("{word} ")))
                    .collect();
                return stack("recovery-key-grid recovery-key-current", words);
            }
            if !fingerprint.is_empty() {
                paragraph(
                    "recovery-key-masked recovery-key-current",
                    "•••• •••• •••• •••• •••• •••• •••• ••••",
                )
            } else {
                stack(
                    "recovery-key-empty recovery-key-current",
                    vec![
                        recovery_label(context.translated(scope, "recovery.panel.not_generated")),
                        paragraph(
                            "muted",
                            context.translated(scope, "recovery.panel.not_generated_hint"),
                        ),
                    ],
                )
            }
        },
    );
    let form_context = context.clone();
    let form = reactive(live, move |scope, key| {
        if key.is_empty() {
            return empty();
        }
        let context = form_context.clone();
        stack(
            "workflow-form recovery-key-confirm-form",
            vec![
                recovery_warning(
                    scope,
                    context.clone(),
                    "recovery-key-live-warning",
                    "recovery.panel.write_down_title",
                    "recovery.panel.write_down_body",
                ),
                field(
                    scope,
                    context.clone(),
                    "recovery-key-confirm-input",
                    "recovery.panel.confirm_label",
                    confirmed,
                    true,
                    true,
                    move |next| confirmed.revise(|value| *value = next),
                ),
                paragraph(
                    "muted",
                    context.translated(scope, "recovery.panel.confirm_hint"),
                ),
            ],
        )
    });
    let generate = state.clone();
    let publish = state.clone();
    let copy_state = state.clone();
    let copy_owner = scope.downgrade();
    let retry = state.confirmation;
    let material = context.clone();
    let generate_enabled = scope.bond(move || {
        phase.get() != EnrollPhase::Publishing
            && !(phase.get() == EnrollPhase::Idle
                && (!fingerprint.get().is_empty()
                    || material
                        .state_store
                        .read(crate::components::mls_recovery_backup_configured)))
    });
    let live_enabled =
        scope.bond(move || !live.get().is_empty() && phase.get() != EnrollPhase::Publishing);
    let recovery_status = state.status;
    let unauthorized = state.unauthorized;
    let nav = context.clone();
    let unauthorized_link = reactive(unauthorized, move |scope, show| {
        if show {
            let nav = nav.clone();
            action(
                scope,
                nav.clone(),
                "recovery-key-goto-devices",
                "recovery.panel.goto_devices",
                "secondary",
                true,
                move || nav.navigate(crate::routes::Route::SettingsDevices),
            )
        } else {
            empty()
        }
    });
    let inventory = state.clone();
    let clear = state.clone();
    let rows = state.rows;
    let loading = state.inventory_busy;
    let rows_context = context.clone();
    let inventory_loaded = state.inventory_loaded;
    let history = reactive(rows, move |scope, rows| {
        let context = rows_context.clone();
        let rows = sorted_backups_latest_first(&rows);
        let total = rows.len();
        let mut children = Vec::new();
        if rows.is_empty() {
            return paragraph(
                "muted restore-empty",
                context.translated(
                    scope,
                    if inventory_loaded.get() {
                        "recovery.panel.no_backups"
                    } else {
                        "recovery.panel.not_loaded"
                    },
                ),
            );
        }
        let latest = &rows[0];
        children.push(line(
            "restore-backup-overview",
            vec![
                card(
                    scope,
                    context.clone(),
                    "recovery.panel.last_backup",
                    vec![
                        plain(fmt_relative(&latest.created_at)),
                        paragraph("muted", fmt_backup_timestamp(&latest.created_at)),
                    ],
                ),
                card(
                    scope,
                    context.clone(),
                    "recovery.panel.backups_found",
                    vec![
                        plain(total.to_string()),
                        paragraph(
                            "muted",
                            context.translated(scope, "recovery.panel.snapshots"),
                        ),
                    ],
                ),
            ],
        ));
        let mut times = Vec::new();
        for (index, row) in rows.iter().take(RESTORE_BACKUP_TIME_LIMIT).enumerate() {
            let mut details = vec![stack(
                "restore-time-copy",
                vec![
                    plain(fmt_relative(&row.created_at)),
                    paragraph(
                        "restore-time-secondary",
                        fmt_backup_timestamp(&row.created_at),
                    ),
                ],
            )];
            if index == 0 {
                details.push(paragraph(
                    "badge green",
                    context.translated(scope, "recovery.panel.latest"),
                ));
            }
            times.push(line(
                if index == 0 {
                    "restore-time-item latest"
                } else {
                    "restore-time-item"
                },
                details,
            ));
        }
        children.push(stack("restore-time-items", times));
        if total > RESTORE_BACKUP_TIME_LIMIT {
            children.push(paragraph(
                "restore-time-more muted",
                crate::i18n::tr_args(
                    "recovery.panel.older_hidden",
                    &[("count", (total - RESTORE_BACKUP_TIME_LIMIT).to_string())],
                ),
            ));
        }
        stack("restore-time-list", children)
    });
    stack(
        "timeline recovery-panel",
        vec![
            stack(
                "event recovery-options",
                vec![
                    line(
                        "event-head",
                        vec![
                            plain(context.translated(scope, "recovery.panel.options")),
                            plain(context.translated(scope, "recovery.recovery_key_section")),
                            crate::components::help_tip(
                                scope,
                                context.clone(),
                                crate::components::HelpTipProps {
                                    text: context.tr("recovery.panel.overview_help"),
                                },
                            ),
                        ],
                    ),
                    stack(
                        "metric-grid recovery-overview",
                        vec![
                            stack(
                                "metric recovery-status-card",
                                vec![
                                    recovery_label(
                                        context.translated(scope, "recovery.recovery_key_section"),
                                    ),
                                    plain(scope.bond(move || {
                                        crate::i18n::tr(match phase.get() {
                                            EnrollPhase::Publishing => {
                                                "recovery.panel.status.publishing"
                                            }
                                            EnrollPhase::CustodyConfirmation => {
                                                "recovery.panel.status.write_down"
                                            }
                                            EnrollPhase::Idle => {
                                                if !fingerprint.get().is_empty() {
                                                    "recovery.panel.status.accepted"
                                                } else if backed_up.get() {
                                                    "recovery.panel.status.unconfirmed"
                                                } else {
                                                    "recovery.panel.status.not_set"
                                                }
                                            }
                                        })
                                    })),
                                    stack(
                                        "muted",
                                        vec![plain(scope.bond(move || match phase.get() {
                                            EnrollPhase::Publishing => {
                                                crate::i18n::tr("recovery.panel.detail.publishing")
                                            }
                                            EnrollPhase::CustodyConfirmation => {
                                                crate::i18n::tr("recovery.panel.detail.custody")
                                            }
                                            EnrollPhase::Idle => {
                                                if !fingerprint.get().is_empty() {
                                                    if rotated.get().is_empty() {
                                                        crate::i18n::tr(
                                                            "recovery.panel.detail.confirmed",
                                                        )
                                                    } else {
                                                        crate::i18n::tr_args(
                                                            "recovery.panel.detail.accepted_at",
                                                            &[(
                                                                "when",
                                                                fmt_relative(&rotated.get()),
                                                            )],
                                                        )
                                                    }
                                                } else if backed_up.get() {
                                                    crate::i18n::tr(
                                                        "recovery.panel.detail.material_elsewhere",
                                                    )
                                                } else {
                                                    crate::i18n::tr(
                                                        "recovery.panel.detail.generate_cta",
                                                    )
                                                }
                                            }
                                        }))],
                                    ),
                                ],
                            ),
                            stack(
                                "metric",
                                vec![
                                    recovery_label(
                                        context.translated(scope, "recovery.panel.protects_title"),
                                    ),
                                    plain(
                                        context.translated(scope, "recovery.panel.protects_value"),
                                    ),
                                    stack(
                                        "muted",
                                        vec![plain(
                                            context
                                                .translated(scope, "recovery.panel.protects_hint"),
                                        )],
                                    ),
                                ],
                            ),
                        ],
                    ),
                ],
            ),
            stack(
                "event recovery-key-section",
                vec![
                    line(
                        "event-head",
                        vec![
                            plain(context.translated(scope, "recovery.recovery_key_section")),
                            plain(context.translated(scope, "recovery.panel.keep_offline")),
                            reactive(backed_up, {
                                let context = context.clone();
                                move |scope, backed| {
                                    crate::components::sync_badge(
                                        scope,
                                        context.clone(),
                                        crate::components::SyncBadgeProps {
                                            state: if backed {
                                                crate::components::SyncBadgeState::Synced
                                            } else {
                                                crate::components::SyncBadgeState::Local
                                            },
                                            local_label: Some(
                                                context.tr("recovery.panel.badge_not_backed_up"),
                                            ),
                                            synced_label: Some(
                                                context.tr("recovery.panel.badge_backed_up"),
                                            ),
                                            pending_label: None,
                                            failed_label: None,
                                            test_id: Some("recovery-key-sync-badge".into()),
                                        },
                                    )
                                }
                            }),
                            crate::components::help_tip(
                                scope,
                                context.clone(),
                                crate::components::HelpTipProps {
                                    text: context.tr("recovery.panel.key_help"),
                                },
                            ),
                        ],
                    ),
                    stack("recovery-key-hero", vec![hero]),
                    form,
                    reactive(
                        scope.bond(move || (live.get().is_empty(), fingerprint.get().is_empty())),
                        {
                            let context = context.clone();
                            move |scope, (no_live, no_fingerprint)| {
                                if no_live && !no_fingerprint {
                                    paragraph(
                                        "muted",
                                        context
                                            .translated(scope, "recovery.panel.plaintext_cleared"),
                                    )
                                } else {
                                    empty()
                                }
                            }
                        },
                    ),
                    reactive(
                        scope.bond(move || {
                            (backed_up.get() || !fingerprint.get().is_empty())
                                && phase.get() == EnrollPhase::Idle
                        }),
                        {
                            let context = context.clone();
                            move |scope, show| {
                                if show {
                                    recovery_warning(
                                        scope,
                                        context.clone(),
                                        "recovery-key-rotation-guard",
                                        "recovery.panel.rotation_guard_title",
                                        "recovery.panel.rotation_guard_body",
                                    )
                                } else {
                                    empty()
                                }
                            }
                        },
                    ),
                    line(
                        "recovery-key-meta",
                        vec![
                            stack(
                                "recovery-key-accepted-meta",
                                vec![
                                    Box::new(glory::prelude::text().class("lbl").content(
                                        context.translated(scope, "recovery.panel.last_accepted"),
                                    )),
                                    Box::new(
                                        glory::prelude::text()
                                            .class("val recovery-key-rotated-at")
                                            .content(
                                                scope.bond(move || fmt_relative(&rotated.get())),
                                            ),
                                    ),
                                    paragraph(
                                        "muted",
                                        context.translated(scope, "recovery.panel.rotate_hint"),
                                    ),
                                ],
                            ),
                            stack(
                                "recovery-key-fingerprint-meta",
                                vec![
                                    Box::new(glory::prelude::text().class("lbl").content(
                                        context.translated(scope, "recovery.panel.fingerprint"),
                                    )),
                                    Box::new(
                                        glory::prelude::text()
                                            .class("val recovery-key-fp")
                                            .content(scope.bond(move || {
                                                let fp = fingerprint.get();
                                                if fp.is_empty() {
                                                    "—".to_owned()
                                                } else {
                                                    let suffix = fp.split(':').nth(1).unwrap_or("");
                                                    if suffix.len() >= 12 {
                                                        format!(
                                                            "sha256:{}…",
                                                            suffix
                                                                .chars()
                                                                .take(12)
                                                                .collect::<String>()
                                                        )
                                                    } else {
                                                        fp
                                                    }
                                                }
                                            })),
                                    ),
                                    paragraph(
                                        "muted",
                                        context
                                            .translated(scope, "recovery.panel.fingerprint_hint"),
                                    ),
                                ],
                            ),
                        ],
                    ),
                    status(recovery_status),
                    unauthorized_link,
                    line(
                        "actions",
                        vec![
                            Box::new(
                                sapid::button()
                                    .unstyled()
                                    .class(scope.bond(move || {
                                        format!(
                                            "recovery-key-regenerate {}",
                                            if phase.get() == EnrollPhase::CustodyConfirmation {
                                                "secondary"
                                            } else {
                                                "primary"
                                            }
                                        )
                                    }))
                                    .label(scope.bond(move || {
                                        crate::i18n::tr(if phase.get() == EnrollPhase::Publishing {
                                            "recovery.panel.publishing_button"
                                        } else if phase.get() == EnrollPhase::CustodyConfirmation {
                                            "recovery.panel.start_over"
                                        } else if fingerprint.get().is_empty() {
                                            "recovery.panel.generate"
                                        } else {
                                            "recovery.panel.handoff_required"
                                        })
                                    }))
                                    .enabled(generate_enabled)
                                    .on_press(move || generate.generate()),
                            ),
                            action(
                                scope,
                                context.clone(),
                                "recovery-key-copy",
                                "recovery.panel.copy",
                                "secondary",
                                live_enabled,
                                move || {
                                    copy_recovery_text_to_clipboard(&copy_state.live.get());
                                    copy_state.copied.revise(|value| *value = true);
                                    let copied = copy_state.copied;
                                    if let Some(scope) = copy_owner.upgrade() {
                                        spawn(&scope, async move {
                                            crate::runtime_helpers::sleep_for(
                                                std::time::Duration::from_secs(2),
                                            )
                                            .await;
                                            copied.revise(|value| *value = false);
                                        });
                                    }
                                },
                            ),
                            action(
                                scope,
                                context.clone(),
                                "recovery-key-confirm-retry",
                                "recovery.panel.retry",
                                "secondary",
                                live_enabled,
                                move || retry.revise(|value| value.clear()),
                            ),
                            action(
                                scope,
                                context.clone(),
                                "recovery-key-clear-live",
                                "recovery.panel.confirm_publish",
                                "secondary",
                                live_enabled,
                                move || publish.confirm(),
                            ),
                        ],
                    ),
                ],
            ),
            recovery_fold(
                scope,
                context.clone(),
                "restore-section",
                "recovery.panel.history_title",
                "recovery.panel.history_subtitle",
                Some("recovery.panel.history_help"),
                vec![
                    line(
                        "actions",
                        vec![
                            {
                                let cursor = state.cursor;
                                let label_context = context.clone();
                                Box::new(
                                    sapid::button()
                                        .unstyled()
                                        .class("btn primary restore-list-button")
                                        .label(scope.bond(move || {
                                            label_context.tr(if loading.get() {
                                                "recovery.panel.loading"
                                            } else if cursor.get().is_some() {
                                                "recovery.panel.next_page"
                                            } else {
                                                "recovery.panel.refresh"
                                            })
                                        }))
                                        .enabled(scope.bond(move || !loading.get()))
                                        .on_press(move || inventory.inventory()),
                                ) as View
                            },
                            action(
                                scope,
                                context.clone(),
                                "restore-clear-button",
                                "recovery.panel.clear",
                                "secondary",
                                scope.bond(move || !loading.get() && !rows.get().is_empty()),
                                move || {
                                    clear.rows.revise(|value| value.clear());
                                    clear.cursor.revise(|value| *value = None);
                                    clear.inventory_loaded.revise(|value| *value = false);
                                    clear.inventory_status.revise(|value| {
                                        *value = clear.context.tr("recovery.panel.cleared")
                                    });
                                },
                            ),
                        ],
                    ),
                    status(state.inventory_status),
                    reactive(state.cursor, {
                        let context = context.clone();
                        move |scope, cursor| {
                            if cursor.is_some() {
                                paragraph(
                                    "muted restore-partial-page",
                                    context.translated(scope, "recovery.panel.partial_page"),
                                )
                            } else {
                                empty()
                            }
                        }
                    }),
                    history,
                ],
            ),
            recovery_fold(
                scope,
                context.clone(),
                "recovery-writeback-explainer",
                "recovery.panel.writeback_title",
                "recovery.panel.writeback_subtitle",
                None,
                vec![paragraph(
                    "muted",
                    context.translated(scope, "recovery.panel.writeback_body"),
                )],
            ),
        ],
    )
}
