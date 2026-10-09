//! Protected E2EE cache occupancy, browser quota, and explicit cleanup controls.

use dioxus::prelude::*;

use crate::state::{BrowserStorageEstimate, E2eePlaintextCacheClearScope, E2eePlaintextCacheUsage};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::dialog::Dialog;
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

async fn refresh_browser_storage_quota(
    mut quota: Signal<Option<BrowserStorageEstimate>>,
    mut status: Signal<StorageFeedback>,
) {
    quota.set(None);
    status.set(StorageFeedback::Message("settings.storage.checking"));
    match crate::state::browser_storage_estimate().await {
        Ok(Some(estimate)) => {
            quota.set(Some(estimate));
            status.set(StorageFeedback::Empty);
        }
        Ok(None) => status.set(StorageFeedback::Message("settings.storage.browser_only")),
        Err(error) => status.set(StorageFeedback::Error(
            "settings.storage.quota_error",
            error.to_string(),
        )),
    }
}

#[component]
pub(super) fn E2eeStorageManagement(principal_id: String, device_id: String) -> Element {
    let session = crate::app::SessionContext::get();
    let mut state_store = session.state_store;
    if session.active_account().is_none() {
        return rsx! {};
    }
    let mut cache_usage = use_signal(|| state_store.read().e2ee_plaintext_cache_usage());
    let mut pending_clear = use_signal(|| None::<E2eePlaintextCacheClearScope>);
    let mut cache_status = use_signal(StorageFeedback::default);
    let browser_quota = use_signal(|| None::<BrowserStorageEstimate>);
    let browser_quota_status = use_signal(StorageFeedback::default);
    use_future(move || refresh_browser_storage_quota(browser_quota, browser_quota_status));

    let usage: E2eePlaintextCacheUsage = cache_usage();
    let quota = browser_quota();
    let quota_status_text = browser_quota_status().text();
    let cache_status_text = cache_status().text();

    rsx! {
        div { class: "event", "data-testid": "browser-storage-quota",
            div { class: "event-head",
                span { {crate::i18n::tr("settings.storage.quota_title")} }
                if quota.is_some_and(|estimate| estimate.is_near_quota()) {
                    span {
                        class: "badge badge-warning",
                        "data-testid": "browser-storage-quota-warning",
                        {crate::i18n::tr("settings.storage.low_space")}
                    }
                } else {
                    span { class: "badge badge-info", {crate::i18n::tr("settings.storage.origin_total")} }
                }
            }
            if let Some(estimate) = quota {
                div { class: "metric",
                    strong { {crate::i18n::tr("settings.storage.used_available")} }
                    span { "{browser_storage_summary(estimate)}" }
                }
                if estimate.is_near_quota() {
                    div { class: "callout warn",
                        div { class: "body",
                            strong { {crate::i18n::tr("settings.storage.quota_warning")} }
                            div { {crate::i18n::tr("settings.storage.quota_guidance")} }
                        }
                    }
                }
            } else {
                div { class: "muted", "{quota_status_text}" }
            }
        }

        div { class: "event", "data-testid": "e2ee-plaintext-cache",
            div { class: "event-head",
                span { {crate::i18n::tr("settings.storage.cache_title")} }
                span { {crate::i18n::tr("settings.storage.manual_only")} }
            }
            div { class: "metric-grid",
                div { class: "metric",
                    strong { {crate::i18n::tr("settings.storage.plaintext")} }
                    span { "{format_storage_bytes(usage.plaintext_bytes as u64)}" }
                }
                div { class: "metric",
                    strong { {crate::i18n::tr("settings.storage.entries")} }
                    span { {crate::i18n::tr_args("settings.storage.entry_summary", &[("entries", usage.entry_count().to_string()), ("realms", usage.realms.len().to_string())])} }
                }
            }
            div { class: "callout warn",
                div { class: "body",
                    strong { {crate::i18n::tr("settings.storage.eviction_disabled")} }
                    div {
                        {crate::i18n::tr("settings.storage.cache_warning")}
                    }
                }
            }
            if usage.realms.is_empty() {
                div { class: "muted", {crate::i18n::tr("settings.storage.empty")} }
            } else {
                div { class: "metric-grid", "data-testid": "e2ee-cache-realm-usage",
                    for (realm_id, realm_usage) in &usage.realms {
                        {
                            let realm_id_for_clear = realm_id.clone();
                            let realm_label = short_protocol_id(realm_id);
                            rsx! {
                                div { class: "metric", key: "{realm_id}",
                                    strong { title: "{realm_id}", "{realm_label}" }
                                    span {
                                        {crate::i18n::tr_args("settings.storage.realm_summary", &[("bytes", format_storage_bytes(realm_usage.plaintext_bytes as u64)), ("entries", realm_usage.entry_count().to_string()), ("authored", realm_usage.authored_entries.to_string()), ("received", realm_usage.received_entries.to_string())])}
                                    }
                                    div { class: "actions",
                                        Button {
                                            variant: ButtonVariant::Destructive,
                                            size: ButtonSize::Sm,
                                            "data-testid": "e2ee-cache-clear-realm",
                                            onclick: move |_| pending_clear.set(Some(
                                                E2eePlaintextCacheClearScope::Realm(
                                                    realm_id_for_clear.clone(),
                                                ),
                                            )),
                                            {crate::i18n::tr("settings.storage.clear_realm")}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            div { class: "actions",
                Button {
                    variant: ButtonVariant::Secondary,
                    size: ButtonSize::Sm,
                    "data-testid": "e2ee-cache-refresh",
                    onclick: move |_| {
                        cache_usage.set(state_store.read().e2ee_plaintext_cache_usage());
                        spawn(refresh_browser_storage_quota(browser_quota, browser_quota_status));
                    },
                    {crate::i18n::tr("common.refresh")}
                }
                Button {
                    variant: ButtonVariant::Destructive,
                    size: ButtonSize::Sm,
                    "data-testid": "e2ee-cache-clear-all",
                    disabled: usage.entry_count() == 0,
                    onclick: move |_| pending_clear.set(Some(E2eePlaintextCacheClearScope::All)),
                    {crate::i18n::tr("settings.storage.clear_all")}
                }
            }
            if !cache_status_text.is_empty() {
                div { class: "muted", role: "status", "{cache_status_text}" }
            }
        }

        if let Some(clear_scope) = pending_clear() {
            {
                let clear_scope_for_action = clear_scope.clone();
                let clear_target = clear_target_text(&clear_scope);
                rsx! {
                    Dialog {
                        open: true,
                        on_open_change: move |open: bool| {
                            if !open {
                                pending_clear.set(None);
                            }
                        },
                        "data-testid": "e2ee-cache-clear-modal",
                        "aria-labelledby": "e2ee-cache-clear-title",
                        div { class: "modal event",
                            div { class: "modal-head event-head",
                                h3 {
                                    id: "e2ee-cache-clear-title",
                                    {crate::i18n::tr_args("settings.storage.clear_title", &[("target", clear_target.clone())])}
                                }
                                span { class: "badge red", {crate::i18n::tr("settings.storage.irreversible")} }
                            }
                            div { class: "modal-body",
                                p {
                                    {crate::i18n::tr_args("settings.storage.clear_body", &[("target", clear_target.clone())])}
                                }
                            }
                            div { class: "modal-foot actions",
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "e2ee-cache-clear-cancel",
                                    onclick: move |_| pending_clear.set(None),
                                    {crate::i18n::tr("common.cancel")}
                                }
                                Button {
                                    variant: ButtonVariant::Destructive,
                                    "data-testid": "e2ee-cache-clear-confirm",
                                    onclick: move |_| {
                                        let clear_scope = clear_scope_for_action.clone();
                                        spawn(async move {
                                            let secure_store =
                                                crate::secure_key_store::default_secure_key_store("inkson");
                                            let pending = state_store
                                                .write()
                                                .prepare_e2ee_plaintext_cache_clear(&clear_scope);
                                            let result = match pending {
                                                Ok(Some(pending)) => {
                                                    if let Err(error) =
                                                        pending.persist(secure_store.as_ref()).await
                                                    {
                                                        state_store
                                                            .write()
                                                            .rollback_e2ee_plaintext_cache_clear(
                                                                pending,
                                                            );
                                                        Err(error)
                                                    } else {
                                                        Ok(Some(()))
                                                    }
                                                }
                                                Ok(None) => Ok(None),
                                                Err(error) => Err(error),
                                            };
                                            match result {
                                                Ok(Some(())) => cache_status.set(
                                                    StorageFeedback::Message("settings.storage.cleared"),
                                                ),
                                                Ok(None) => cache_status
                                                    .set(StorageFeedback::Message("settings.storage.no_match")),
                                                Err(error) => cache_status.set(StorageFeedback::Error("settings.storage.clear_error", error.to_string())),
                                            }
                                            cache_usage.set(
                                                state_store.read().e2ee_plaintext_cache_usage(),
                                            );
                                            pending_clear.set(None);
                                        });
                                    },
                                    {crate::i18n::tr("settings.storage.clear_confirm")}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
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
    fn completed_storage_feedback_retranslates_without_changing_error_detail() {
        let mut dom = VirtualDom::new(|| rsx! {});
        dom.rebuild_in_place();
        dom.in_scope(ScopeId::ROOT, || {
            let mut locale = provide_context(crate::i18n::init_i18n_with_locale(
                crate::i18n::UiLocale::En,
            ));
            let error = StorageFeedback::Error(
                "settings.storage.quota_error",
                "quota-test-detail / 原文".into(),
            );
            let completed = StorageFeedback::Message("settings.storage.cleared");
            assert_eq!(
                error.text(),
                "Browser quota unavailable: quota-test-detail / 原文"
            );
            assert!(completed.text().starts_with("Protected plaintext cleared."));
            crate::i18n::set_locale(&mut locale, crate::i18n::UiLocale::Zh);
            assert_eq!(error.text(), "无法获取浏览器配额：quota-test-detail / 原文");
            assert!(completed.text().starts_with("受保护的明文已清理。"));
            crate::i18n::set_locale(&mut locale, crate::i18n::UiLocale::En);
            assert_eq!(
                error.text(),
                "Browser quota unavailable: quota-test-detail / 原文"
            );
        });
    }

    #[test]
    fn cleanup_confirmation_keeps_scope_and_irreversibility_in_both_languages() {
        let mut dom = VirtualDom::new(|| rsx! {});
        dom.rebuild_in_place();
        dom.in_scope(ScopeId::ROOT, || {
            let mut locale = provide_context(crate::i18n::init_i18n_with_locale(
                crate::i18n::UiLocale::En,
            ));
            for (language, all, warning) in [
                (
                    crate::i18n::UiLocale::En,
                    "all Realms",
                    "This cannot be undone.",
                ),
                (crate::i18n::UiLocale::Zh, "全部 Realm", "此操作无法撤销。"),
            ] {
                crate::i18n::set_locale(&mut locale, language);
                assert_eq!(clear_target_text(&E2eePlaintextCacheClearScope::All), all);
                let target =
                    clear_target_text(&E2eePlaintextCacheClearScope::Realm("realm-test".into()));
                assert!(target.contains(&short_protocol_id("realm-test")));
                let body = crate::i18n::tr_args(
                    "settings.storage.clear_body",
                    &[("target", target.clone())],
                );
                assert!(body.contains(&target));
                assert!(body.contains(warning));
                assert!(body.contains("MLS"));
            }
        });
    }
}
