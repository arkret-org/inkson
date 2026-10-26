//! Settings surface.
//!
//! Territory split (preserved from former sibling files):
//! - G3.Y1 (device management): [`devices`].
//! - G3.Y3 (policy / capabilities): [`blocklist`], [`capabilities`].
//! The aggregate routing entry + the generic profile card live in
//! this `mod.rs`.

pub mod blocklist;
pub mod capabilities;
pub mod consent;
pub mod devices;
/// U4 - "who can invite me" invite_receive_policy editor.
pub mod invite_policy;
pub mod mls_recovery;
pub mod storage;

pub(crate) mod account_data;
mod controller;
pub mod invite_locator;
mod model;
mod profile_helpers;
pub mod realm_picker;
mod sections;
pub(crate) mod widgets;

use std::rc::Rc;

use account_data::*;
use arkret_wire::AccountDataKey;
use base64::Engine as _;
use glory::Scope;
use glory::prelude::Widget;
use invite_locator::*;
use profile_helpers::*;
use realm_picker::{preference_realm_options, selected_realm_id};
use sections::*;
use serde_json::{Map, Value, json};
use widgets::*;

use crate::i18n::UiLocale;
use crate::notification_rules::WatchLevel;
use crate::presentation::{InksonContext, SharedStateStore, View};
use crate::routes::Route;
use crate::transport::auth::{with_authed_sdk_client, with_event_submitter};
use crate::views::helpers::{actor_display_label, short_protocol_id};

/// Resolve the relative expiry picker choice into a typed UTC `clears_at`
/// (profiles-presence.md §3.6). `never` (and anything unrecognized) means no
/// expiry; canonical wire formatting remains owned by the SDK serializer.
pub(crate) fn presence_expiry_to_clears_at(choice: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let now = chrono::Utc::now();
    let clears_at = match choice {
        "30m" => now + chrono::Duration::minutes(30),
        "1h" => now + chrono::Duration::hours(1),
        "today" => {
            let next_midnight = now.date_naive().succ_opt()?.and_hms_opt(0, 0, 0)?;
            chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(next_midnight, chrono::Utc)
        }
        _ => return None,
    };
    Some(clears_at)
}

/// A4a — push the current `ak.client.ui_state` payload (theme + sidebar
/// collapsed) to coland's `ak.account_data.set` endpoint so other
/// devices pick up the same preference.
///
/// `local_theme` MUST already match the local `LocalConfigStore` write —
/// we never re-read it from the store here because the Signal copy from
/// the caller is the freshest one.
pub(crate) fn push_client_ui_account_data(
    context: Rc<InksonContext>,
    base_url: String,
    api_token: String,
    local_theme: String,
) {
    push_client_ui_account_data_patches(
        context.clone(),
        base_url,
        api_token,
        vec![crate::account_data::ClientUiStatePatch::Theme(local_theme)],
    );
}

/// A locale's name written in that locale, so a user who cannot read the
/// current UI language can still find their own.
fn locale_display_name(locale: UiLocale) -> &'static str {
    match locale {
        UiLocale::En => "English",
        UiLocale::Zh => "中文",
    }
}

/// Apply a language choice and persist it everywhere it needs to go.
///
/// Three writes, none of them optional:
///
/// 1. the live signal, so the UI switches now;
/// 2. the device preference, which is what seeds the *next* launch before a session exists — and
///    what the OIDC `ui_locales` parameter is built from, so coauth follows on the next sign-in;
/// 3. the `language` field of the `ak.client.ui_state` account-data entry (spec
///    `discovery/client-preferences.md` §3.4), which is how the user's other devices find out.
fn select_locale(context: Rc<InksonContext>, choice: UiLocale) {
    if context.locale.get() == choice {
        return;
    }
    context.locale.revise(|value| {
        *value = choice;
    });
    context
        .state_store
        .write(|store| store.set_device_pref("locale", choice.code()));
    push_client_language_account_data(
        context.clone(),
        context.base_url.get(),
        context.token.get(),
        choice,
    );
}

/// Best-effort cross-device sync of the language choice.
///
/// The choice is written into the `language` field of the registered
/// `ak.client.ui_state` cell (spec `discovery/client-preferences.md` §3.4)
/// through the CAS read-merge-write loop in
/// [`crate::transport::account::update_account_data_with_merge`], so theme,
/// `recent_realms`, `avatar_blob_ref` and every other field of the cell
/// survive the update.
///
/// Mirrors [`push_client_ui_account_data_with_avatar`]: signed-out is a no-op
/// (the device preference already holds the choice and the next sign-in
/// republishes it), and a failed write is logged rather than surfaced — the
/// user can see the language changed, and telling them the sync failed gives
/// them nothing to act on.
pub(crate) fn push_client_language_account_data(
    context: Rc<InksonContext>,
    base_url: String,
    api_token: String,
    locale: UiLocale,
) {
    push_client_ui_account_data_patches(
        context.clone(),
        base_url,
        api_token,
        vec![crate::account_data::ClientUiStatePatch::Language(locale)],
    );
}

/// Best-effort field-level update of the encrypted `ak.client.ui_state` cell.
/// All writers share the account-data CAS read/merge/write loop so retries
/// always reapply the patch to the latest server snapshot.
fn push_client_ui_account_data_patches(
    context: Rc<InksonContext>,
    base_url: String,
    api_token: String,
    patches: Vec<crate::account_data::ClientUiStatePatch>,
) {
    if api_token.trim().is_empty() {
        return;
    }
    let Some(authority) =
        crate::secure_key_store::active_device_seed_scope().map(|scope| scope.authority)
    else {
        return;
    };
    {
        let task_owner = context.clone();
        let _ = task_owner.spawn(async move {
            if let Err(err) = with_event_submitter(&base_url, api_token, |sub| async move {
                crate::transport::account::update_account_data_with_merge(
                    &sub,
                    AccountDataKey::CLIENT_UI_STATE,
                    |snapshot| {
                        let mut plaintext = match snapshot.entry.as_ref() {
                            Some(entry) => crate::account_data::decrypt_account_data_entry(
                                &authority,
                                AccountDataKey::CLIENT_UI_STATE,
                                entry,
                            )?,
                            None => serde_json::json!({}),
                        };
                        crate::account_data::apply_client_ui_state_patches(
                            &mut plaintext,
                            &patches,
                        );
                        crate::account_data::encrypt_account_data_value(
                            &authority,
                            AccountDataKey::CLIENT_UI_STATE,
                            &plaintext,
                        )
                    },
                )
                .await
            })
            .await
            {
                tracing::warn!(
                    "ak.account_data.set for ak.client.ui_state failed: {}",
                    err.display()
                );
            }
        });
    };
}

/// A4b — variant of [`push_client_ui_account_data`] that also carries
/// the most-recently uploaded `avatar_blob_ref`. The avatar itself is
/// also published via `ak.self.account.command.update_profile.v1` so other actors see
/// it through the directory; mirroring the ref into `ak.client.ui_state` keeps a
/// second device that signs in primed before the profile lookup
/// completes.
///
/// Pass `None` to skip the avatar mirror (theme-only sync). Pass
/// `Some("")` to tombstone the cached ref so other devices fall back to
/// the public profile when the avatar is cleared.
pub(crate) fn push_client_ui_account_data_with_avatar(
    context: Rc<InksonContext>,
    base_url: String,
    api_token: String,
    local_theme: String,
    avatar_blob_ref: Option<String>,
) {
    let mut patches = vec![crate::account_data::ClientUiStatePatch::Theme(local_theme)];
    if let Some(avatar_blob_ref) = avatar_blob_ref {
        patches.push(crate::account_data::ClientUiStatePatch::AvatarBlobRef(
            avatar_blob_ref,
        ));
    }
    push_client_ui_account_data_patches(context.clone(), base_url, api_token, patches);
}

/// Build the canonical `content` body for a read-receipt preferences
/// account-data entry. Mirrors the SDK's `ReadReceiptPreferences` shape so
/// other devices reading the value via `/sync` get the same field names.
pub(crate) fn build_read_receipt_preferences_body(
    default_send: bool,
    default_display: bool,
    realm_send_overrides: &std::collections::BTreeMap<String, bool>,
    realm_display_overrides: &std::collections::BTreeMap<String, bool>,
    strand_send_overrides: &std::collections::BTreeMap<String, bool>,
    strand_display_overrides: &std::collections::BTreeMap<String, bool>,
) -> serde_json::Value {
    fn scope_map(
        send_overrides: &std::collections::BTreeMap<String, bool>,
        display_overrides: &std::collections::BTreeMap<String, bool>,
    ) -> Value {
        let ids: std::collections::BTreeSet<String> = send_overrides
            .keys()
            .chain(display_overrides.keys())
            .cloned()
            .collect();
        let mut scopes = Map::new();
        for id in ids {
            let mut pref = Map::new();
            if let Some(send) = send_overrides.get(&id) {
                pref.insert("send".to_owned(), Value::Bool(*send));
            }
            if let Some(display) = display_overrides.get(&id) {
                pref.insert("display".to_owned(), Value::Bool(*display));
            }
            scopes.insert(id, Value::Object(pref));
        }
        Value::Object(scopes)
    }

    json!({
        "default": {
            "send": default_send,
            "display": default_display,
        },
        "realms": scope_map(realm_send_overrides, realm_display_overrides),
        "strands": scope_map(strand_send_overrides, strand_display_overrides),
    })
}

/// Push the actor-private personal blocklist to coland. Local state is
/// authoritative; network errors are logged only so privacy controls keep
/// working offline.
pub(crate) fn push_blocklist_account_data(
    context: Rc<InksonContext>,
    base_url: String,
    api_token: String,
    principal_id: String,
    state_store: SharedStateStore,
    entries: Vec<arkret_models_collaboration::objects::productivity::AccountBlocklistEntry>,
) {
    if api_token.trim().is_empty() {
        return;
    }
    let Some(authority) =
        crate::secure_key_store::active_device_seed_scope().map(|scope| scope.authority)
    else {
        tracing::warn!("blocklist upload skipped: active account scope is unavailable");
        return;
    };
    if principal_id != authority.principal_id.as_str() {
        tracing::warn!("blocklist upload skipped: active authority does not match the account");
        return;
    }
    let store = state_store.handle();
    {
        let task_owner = context.clone();
        let _ = task_owner.spawn(async move {
            match with_event_submitter(&base_url, api_token, |sub| async move {
                crate::transport::account::persist_personal_block_saga(
                    &sub, &authority, &store, &entries,
                )
                .await
            })
            .await
            {
                Ok(_) => {}
                Err(err) => {
                    tracing::debug!("personal blocklist saga deferred: {}", err.display());
                }
            }
        });
    };
}

/// Client-side DNS-domain sanity check for the blocklist `domain` target
/// (`client-preferences.md` §3.5 / `content-moderation.md` §4.3). Like
/// the ActorId parser used by the blocklist card, this only powers *live*
/// form feedback. The wire value is normalized by
/// `account_data::normalize_blocklist_value`. A domain target remains a private
/// string filter; it does not resolve or prove Actor, service, Organization, or
/// Realm affiliation.
/// Accepts a bare multi-label domain (`example.com`, `sub.acme.example`);
/// rejects schemes, ports, paths, whitespace, `@`, and single-label inputs.
pub(crate) fn is_likely_valid_domain(input: &str) -> bool {
    let value = input.trim();
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    if value.contains(|c: char| c.is_whitespace())
        || value.contains('/')
        || value.contains(':')
        || value.contains('@')
    {
        return false;
    }
    let labels: Vec<&str> = value.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Spec client-preferences.md §3.7: push (or tombstone) a Realm remark to
/// coland via `ak.account_data.set`. Local state is authoritative and the
/// server write is best-effort. `remark.is_empty()` triggers a DELETE so the
/// row tombstones cleanly across devices.
pub(crate) fn push_realm_remark_account_data(
    context: Rc<InksonContext>,
    base_url: String,
    api_token: String,
    realm_id: String,
    remark: crate::account_data::RealmRemark,
) {
    push_realm_remark_account_data_impl(
        context.clone(),
        base_url,
        api_token,
        realm_id,
        remark,
        false,
    );
}

/// Variant of [`push_realm_remark_account_data`] that surfaces sync failures
/// to the user via an error toast (`realm.pin_failed`).
pub(crate) fn push_realm_remark_account_data_with_failure_toast(
    context: Rc<InksonContext>,
    base_url: String,
    api_token: String,
    realm_id: String,
    remark: crate::account_data::RealmRemark,
) {
    push_realm_remark_account_data_impl(
        context.clone(),
        base_url,
        api_token,
        realm_id,
        remark,
        true,
    );
}

/// Apply one holder-authored Contact remark edit through the account-data
/// whole-value CAS binding.
///
/// The edit, not the assembled record, is what travels: the merge re-reads the
/// authoritative value on every attempt and re-applies just the edited field, so
/// a concurrent write from the holder's second device keeps its petname, note,
/// tags, pin and confirmation baseline instead of being overwritten by whatever
/// this device had rendered (`client-preferences.md` section 3.6).
pub(crate) fn push_contact_remark_edit(
    context: Rc<InksonContext>,
    base_url: String,
    api_token: String,
    principal_id: arkret_sdk::DidCoreId,
    edit: crate::account_data::ContactRemarkEdit,
) {
    let Some(authority) =
        crate::secure_key_store::active_device_seed_scope().map(|scope| scope.authority)
    else {
        tracing::warn!("contact remark upload skipped: active account scope is unavailable");
        return;
    };
    {
        let task_owner = context.clone();
        let _ = task_owner.spawn(async move {
        if let Err(error) =
            save_contact_remark_edit(base_url, api_token, authority, principal_id, edit).await
        {
            tracing::warn!(error = %error.display(), "contact remark account_data write failed");
        }
    });
    };
}

/// Return the authoritative merged remark only after the service accepted it.
pub(crate) async fn save_contact_remark_edit(
    base_url: String,
    api_token: String,
    authority: arkret_sdk::AccountId,
    principal_id: arkret_sdk::DidCoreId,
    edit: crate::account_data::ContactRemarkEdit,
) -> Result<crate::account_data::ContactRemark, crate::transport::auth::ApiCallError> {
    use crate::transport::auth::ApiCallError;
    let namespace_key = crate::account_data::account_data_namespace_key(&authority)
        .map_err(ApiCallError::Failed)?;
    let key = crate::account_data::contact_remark_account_data_key(&namespace_key, &principal_id)
        .map_err(ApiCallError::Failed)?;
    with_event_submitter(&base_url, api_token, move |sub| async move {
        anyhow::ensure!(
            sub.authority()? == &authority,
            "Contact remark account changed"
        );
        let result = crate::transport::account::update_account_data_with_conditional_merge(
            &sub,
            &key,
            |snapshot| {
                let merged = crate::account_data::merge_contact_remark_account_data(
                    &authority,
                    &key,
                    &principal_id,
                    &edit,
                    snapshot.entry.as_ref(),
                )?;
                Ok(match merged {
                    crate::account_data::ContactRemarkMerge::Write(body) => {
                        crate::transport::account::AccountDataMergeDecision::Replace(body)
                    }
                    crate::account_data::ContactRemarkMerge::Delete => {
                        crate::transport::account::AccountDataMergeDecision::Delete
                    }
                })
            },
        )
        .await?;
        if result.is_null() {
            return Ok(crate::account_data::ContactRemark::new(
                principal_id,
                "",
                chrono::Utc::now(),
            ));
        }
        let row: arkret_sdk::AccountDataEntry = serde_json::from_value(result)?;
        let remark: crate::account_data::ContactRemark = serde_json::from_value(
            crate::account_data::decrypt_account_data_entry(&authority, &key, &row)?,
        )?;
        remark.validate_for_account_data_key(&namespace_key, &key)?;
        Ok(remark)
    })
    .await
}

mod preferences;
mod profile;

pub fn page(scope: &Scope, context: Rc<InksonContext>, route: Route) -> View {
    let active_section = SettingsSection::from_slug(route.settings_section());
    let nav_filter = scope.cage(String::new());
    let nav_context = context.clone();
    let locale = context.locale;
    let nav = reactive(
        scope.bond(move || (nav_filter.get(), locale.get())),
        move |scope, (filter, _)| {
            let context = nav_context.clone();
            let groups = model::visible_nav_groups(&filter.trim().to_lowercase());
            let mut clusters = Vec::new();
            if groups.is_empty() {
                clusters.push(paragraph(
                    "settings-nav-empty muted",
                    context.translated(scope, "search.no_results"),
                ));
            }
            let group_count = groups.len();
            for (group_index, group) in groups.into_iter().enumerate() {
                let mut items = vec![paragraph(
                    "settings-nav-group-label",
                    context.translated(scope, group.label_key),
                )];
                for section in group.sections {
                    let navigate = context.clone();
                    let label = context.translated(scope, section.label_key());
                    items.push(Box::new(
                        crate::presentation::widgets::internal_link()
                            .class(format!(
                                "settings-nav-item settings-nav-item-{}{}",
                                section.slug(),
                                if section == active_section {
                                    " active"
                                } else {
                                    ""
                                }
                            ))
                            .semantics(Some(Box::new(glory::render::Semantics {
                                current: (section == active_section)
                                    .then_some(glory::render::Current::Page),
                                ..Default::default()
                            })))
                            .name(label)
                            .target(section.route().to_string())
                            .fill(
                                glory::ui::text()
                                    .class("settings-nav-item-title")
                                    .content(label),
                            )
                            .on(glory::render::EventKind::Activate, move |_| {
                                navigate.navigate(section.route())
                            }),
                    ) as View);
                }
                clusters.push(stack("settings-nav-cluster", items));
                if group_index + 1 < group_count {
                    clusters.push(stack("settings-nav-divider", Vec::new()));
                }
            }
            stack("settings-nav-list", clusters)
        },
    );
    let content = match active_section {
        SettingsSection::Account => profile::page(scope, context.clone()),
        SettingsSection::Devices => devices::page(
            scope,
            context.clone(),
            matches!(route, Route::SettingsDevicesPair),
        ),
        SettingsSection::Consent => consent::page(scope, context.clone()),
        SettingsSection::InvitePolicy => invite_policy::page(scope, context.clone()),
        SettingsSection::Capabilities => capabilities::page(scope, context.clone()),
        SettingsSection::Blocklist => blocklist::page(scope, context.clone()),
        SettingsSection::Storage => storage::settings(scope, context.clone()),
        SettingsSection::Encryption => stack(
            "settings-content-stack",
            vec![
                mls_recovery::page(scope, context.clone()),
                key_backup_guidance(scope, context.clone()),
            ],
        ),
        SettingsSection::Notifications => preferences::notifications(scope, context.clone()),
        SettingsSection::Privacy => preferences::privacy(scope, context.clone()),
        SettingsSection::Theme => theme_page(scope, context.clone()),
        SettingsSection::Mimi => mimi_page(scope, context.clone()),
        SettingsSection::Agents => {
            crate::views::agents::page(scope, context.clone(), route.clone())
        }
        SettingsSection::Recovery => {
            crate::views::recovery::page(scope, context.clone(), Route::SettingsRecovery)
        }
        SettingsSection::Contacts => {
            crate::views::contacts::contacts_panel(scope, context.clone(), true)
        }
        SettingsSection::Audit => crate::views::audit::page(scope, context.clone(), Route::Audit),
        SettingsSection::Developer => {
            crate::views::developer::page(scope, context.clone(), Route::Developer)
        }
        SettingsSection::Release => release_page(scope, context.clone()),
        SettingsSection::Server => {
            let push = context.state_store.read(|store| store.push_registration());
            let metric = |title: &str, value: View| {
                stack(
                    "metric",
                    vec![
                        paragraph(
                            "settings-server-metric-label",
                            context.translated(scope, title),
                        ),
                        value,
                    ],
                )
            };
            stack(
                "settings-card-grid",
                vec![stack(
                    "event settings-card-span-2 transport-invariant",
                    vec![
                        line(
                            "event-head",
                            vec![plain(context.translated(scope, "settings.server.context"))],
                        ),
                        line(
                            "metric-grid",
                            vec![
                                metric("settings.server.station", plain(context.base_url)),
                                metric(
                                    "settings.server.session",
                                    plain(context.translated(
                                        scope,
                                        if context.token.get().trim().is_empty() {
                                            "account.not_signed_in"
                                        } else {
                                            "settings.server.session_authenticated"
                                        },
                                    )),
                                ),
                                metric(
                                    "settings.server.push",
                                    plain(crate::push::push_status_label(push.as_ref())),
                                ),
                            ],
                        ),
                    ],
                )],
            )
        }
    };
    stack(
        "settings settings-page",
        vec![stack(
            "settings-shell",
            vec![
                stack(
                    "settings-sidebar-column",
                    vec![
                        stack(
                            "settings-nav-search",
                            vec![widgets::input_prompt(
                                scope,
                                context
                                    .translated(scope, "settings.search.placeholder")
                                    .into(),
                                nav_filter,
                                Box::new(
                                    sapid::text_field()
                                        .unstyled()
                                        .class(
                                            "input settings-nav-search-input settings-nav-search",
                                        )
                                        .name(
                                            context
                                                .translated(scope, "settings.search.placeholder"),
                                        )
                                        .value(nav_filter)
                                        .on_value_change(move |next| {
                                            nav_filter.revise(|value| *value = next)
                                        }),
                                ),
                            )],
                        ),
                        nav,
                    ],
                ),
                stack(
                    "settings-content-column",
                    vec![
                        stack(
                            "event settings-content-hero",
                            vec![heading(
                                2,
                                "settings-content-title",
                                context.translated(scope, active_section.label_key()),
                            )],
                        ),
                        content,
                    ],
                ),
            ],
        )],
    )
}

fn key_backup_guidance(scope: &Scope, context: Rc<InksonContext>) -> View {
    let title = context.translated(scope, "settings.key_backup.title");
    let badge = context.translated(scope, "settings.key_backup.badge");
    Box::new(
        sapid::collapsible("key-backup-guidance")
            .unstyled()
            .class("event key-backup-guidance")
            .label(title)
            .default_open(false)
            .content_policy(sapid::ContentPolicy::KeepMounted)
            .trigger_content(move || {
                glory::ui::group().fill(vec![
                    plain(title),
                    Box::new(glory::ui::text().class("badge amber").content(badge)) as View,
                ])
            })
            .content(move || {
                let context = context.clone();
                glory::ui::widget(move |scope| {
                    let navigate_context = context.clone();
                    let recovery_label =
                        context.translated(scope, "settings.key_backup.open_recovery");
                    glory::ui::group()
                        .fill(vec![
                            paragraph(
                                "muted",
                                context.translated(scope, "settings.key_backup.body"),
                            ),
                            paragraph(
                                "muted",
                                context.translated(scope, "settings.key_backup.open_recovery_hint"),
                            ),
                            line(
                                "actions",
                                vec![Box::new(
                                    crate::presentation::widgets::internal_link()
                                        .class("primary key-backup-open-recovery")
                                        .name(recovery_label)
                                        .target(Route::SettingsRecovery.to_string())
                                        .fill(glory::ui::group().fill(vec![
                                            crate::components::ui_icon("key"),
                                            plain(recovery_label),
                                        ]))
                                        .on(glory::render::EventKind::Activate, move |_| {
                                            navigate_context.navigate(Route::SettingsRecovery);
                                        }),
                                ) as View],
                            ),
                            paragraph(
                                "muted",
                                context.translated(scope, "settings.key_backup.contract"),
                            ),
                        ])
                        .build(scope)
                })
            }),
    )
}

fn theme_page(scope: &Scope, context: Rc<InksonContext>) -> View {
    let persist_context = context.clone();
    let persist: Rc<dyn Fn(String)> = Rc::new(move |next| {
        persist_context
            .state_store
            .write(|store| store.save_plain_local_data("theme", next.clone()));
        push_client_ui_account_data(
            persist_context.clone(),
            persist_context.base_url.get(),
            persist_context.token.get(),
            next,
        );
    });
    let theme = context.theme;
    let locale_state = context.locale;
    let mut icons = Vec::new();
    for (value, label, icon) in [
        ("light", "settings.theme.light", "sun"),
        ("night", "settings.theme.night", "moon"),
        ("system", "settings.theme.system", "monitor"),
    ] {
        let commit = persist.clone();
        let selected = scope.bond(move || theme.get() == value);
        let classes = scope.bond(move || {
            format!(
                "btn icon sm settings-theme-{value} settings-theme-choice {}",
                if selected.get() { "primary" } else { "ghost" }
            )
        });
        let semantics = scope.bond(move || {
            Some(Box::new(glory::render::Semantics {
                pressed: Some(selected.get()),
                ..Default::default()
            }))
        });
        icons.push(Box::new(
            glory::prelude::button()
                .class(classes)
                .name(context.translated(scope, label))
                .semantics(semantics)
                .fill(crate::components::ui_icon(icon))
                .on(glory::render::EventKind::Activate, move |_| {
                    theme.revise(|theme| *theme = value.to_owned());
                    commit(value.to_owned());
                }),
        ) as View);
    }
    let mut languages = Vec::new();
    for locale in [UiLocale::En, UiLocale::Zh] {
        let change = context.clone();
        let class = scope.bond(move || {
            format!(
                "button settings-language-choice {}",
                if locale_state.get() == locale {
                    "primary"
                } else {
                    "secondary"
                }
            )
        });
        languages.push(Box::new(
            sapid::button()
                .unstyled()
                .class(class)
                .label(locale_display_name(locale))
                .on_press(move || select_locale(change.clone(), locale)),
        ) as View);
    }
    stack(
        "settings-card-grid",
        vec![
            stack(
                "event theme-settings",
                vec![
                    line(
                        "event-head",
                        vec![
                            plain(context.translated(scope, "theme.switcher_aria_label")),
                            plain(context.translated(scope, "settings.theme.badge")),
                        ],
                    ),
                    line("actions", icons),
                    paragraph(
                        "muted",
                        scope.bond(move || {
                            crate::i18n::tr_args(
                                "settings.theme.current",
                                &[("theme", theme.get())],
                            )
                        }),
                    ),
                    crate::components::theme_switcher(
                        scope,
                        context.clone(),
                        crate::components::ThemeSwitcherProps {
                            theme,
                            on_persist: persist,
                        },
                    ),
                ],
            ),
            stack(
                "event language-settings",
                vec![
                    line(
                        "event-head",
                        vec![
                            plain(context.translated(scope, "settings.language.title")),
                            Box::new(glory::prelude::text().class("text-direction").content(
                                scope.bond(move || {
                                    locale_state.get().direction().as_str().to_owned()
                                }),
                            )),
                        ],
                    ),
                    line("actions", languages),
                ],
            ),
        ],
    )
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) mod restored_surface_tests;

fn mimi_page(scope: &Scope, context: Rc<InksonContext>) -> View {
    let controller = controller::SettingsController::new(scope, context.clone());
    controller::avatar_selection_boundary(scope, controller.clone());
    fn probe_action(
        scope: &Scope,
        context: Rc<InksonContext>,
        class: &str,
        label: &str,
        busy: glory::Cage<bool>,
        handler: impl FnMut() + 'static,
    ) -> View {
        Box::new(
            sapid::button()
                .unstyled()
                .class(format!("secondary {class}"))
                .label(context.translated(scope, label))
                .enabled(scope.bond(move || !busy.get()))
                .loading(busy)
                .on_press(handler),
        )
    }
    fn output(
        scope: &Scope,
        context: Rc<InksonContext>,
        class: &str,
        value: glory::Cage<String>,
        placeholder: &'static str,
    ) -> View {
        let display = scope.bond(move || {
            let current = value.get();
            if current.is_empty() {
                let _ = context.locale.get();
                context.tr(placeholder)
            } else {
                current
            }
        });
        Box::new(
            glory::ui::text()
                .kind(glory::render::TextKind::Code)
                .class(format!("mimi-result-text {class}"))
                .content(display),
        )
    }
    let directory = controller.clone();
    let directory_context = context.clone();
    let query = controller.clone();
    let query_context = context.clone();
    let submit = controller.clone();
    let submit_context = context.clone();
    let proxy = controller.clone();
    let proxy_context = context.clone();
    stack(
        "settings-content-stack",
        vec![stack(
            "event mimi-interop-panel",
            vec![
                line(
                    "event-head",
                    vec![
                        plain(context.translated(scope, "settings.mimi.title")),
                        plain(context.translated(scope, "settings.group.advanced")),
                    ],
                ),
                line(
                    "actions",
                    vec![
                        probe_action(
                            scope,
                            context.clone(),
                            "mimi-refresh-directory mimi-directory-refresh",
                            "settings.mimi.refresh_directory",
                            controller.mimi_directory_loading,
                            move || {
                                directory.clone().refresh_mimi_directory(
                                    directory_context.base_url.get(),
                                    directory_context.token.get(),
                                )
                            },
                        ),
                        probe_action(
                            scope,
                            context.clone(),
                            "mimi-identifier-query mimi-query-submit",
                            "settings.mimi.identifier_query",
                            controller.mimi_query_loading,
                            move || {
                                query.clone().query_mimi_identifiers(
                                    query_context.base_url.get(),
                                    query_context.token.get(),
                                )
                            },
                        ),
                        probe_action(
                            scope,
                            context.clone(),
                            "mimi-submit-message",
                            "settings.mimi.submit_message",
                            controller.mimi_submit_loading,
                            move || {
                                let Some(account) = submit_context.active_account.get() else {
                                    return;
                                };
                                submit.clone().submit_mimi_message(
                                    submit_context.base_url.get(),
                                    submit_context.token.get(),
                                    arkret_sdk::ActorId::account(account.authority),
                                    account.device_id.to_string(),
                                );
                            },
                        ),
                        probe_action(
                            scope,
                            context.clone(),
                            "mimi-proxy-download",
                            "settings.mimi.proxy_download",
                            controller.mimi_proxy_loading,
                            move || {
                                let Some(account) = proxy_context.active_account.get() else {
                                    return;
                                };
                                proxy.clone().proxy_download_mimi_asset(
                                    proxy_context.base_url.get(),
                                    proxy_context.token.get(),
                                    account.principal_id().to_string(),
                                );
                            },
                        ),
                    ],
                ),
                stack(
                    "event mimi-directory-result",
                    vec![
                        line(
                            "event-head",
                            vec![
                                plain(context.translated(scope, "nav.directory")),
                                plain(context.translated(scope, "settings.mimi.directory_badge")),
                            ],
                        ),
                        output(
                            scope,
                            context.clone(),
                            "mimi-directory-content",
                            controller.mimi_directory,
                            "settings.mimi.not_loaded",
                        ),
                    ],
                ),
                stack(
                    "event mimi-action-receipt",
                    vec![
                        line(
                            "event-head",
                            vec![
                                plain(context.translated(scope, "settings.mimi.receipt_title")),
                                plain(context.translated(scope, "settings.mimi.receipt_badge")),
                            ],
                        ),
                        output(
                            scope,
                            context.clone(),
                            "mimi-query-receipt",
                            controller.mimi_receipt,
                            "settings.mimi.no_receipt",
                        ),
                        output(
                            scope,
                            context.clone(),
                            "mimi-submit-receipt",
                            controller.mimi_submit_receipt,
                            "settings.mimi.no_receipt",
                        ),
                        output(
                            scope,
                            context.clone(),
                            "mimi-proxy-receipt",
                            controller.mimi_proxy_receipt,
                            "settings.mimi.no_receipt",
                        ),
                    ],
                ),
            ],
        )],
    )
}

#[cfg(test)]
mod tests;

fn release_page(scope: &Scope, context: Rc<InksonContext>) -> View {
    let signer = crate::event_signer::signer_status()
        .map(|status| status.signer_did)
        .unwrap_or_else(|| "—".into());
    stack(
        "settings-content-stack",
        vec![stack(
            "event settings-session-diagnostics",
            vec![
                line(
                    "event-head",
                    vec![
                        plain(context.translated(scope, "settings.session_diagnostics.title")),
                        plain(context.translated(scope, "settings.group.advanced")),
                    ],
                ),
                stack(
                    "metric-grid",
                    vec![
                        stack(
                            "metric settings-proof-mode",
                            vec![
                                plain(context.translated(scope, "settings.proof_mode.label")),
                                plain(crate::operation::current_proof_mode().label_en()),
                            ],
                        ),
                        stack(
                            "metric settings-signer-info",
                            vec![
                                plain(context.translated(scope, "settings.signer.label")),
                                paragraph("settings-signer-did", short_protocol_id(&signer)),
                            ],
                        ),
                    ],
                ),
            ],
        )],
    )
}
