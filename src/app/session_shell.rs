use super::*;

/// Session-lifetime owner for global effects and the authenticated/auth shell
/// surface. Bootstrap constructs stable service contexts; this component owns
/// effects that must be torn down when the shell itself is unmounted.
#[component]
pub(super) fn SessionShell(
    locale: Signal<UiLocale>,
    i18n_signal: crate::i18n::I18nSignal,
    base_url: Signal<String>,
    token: Signal<String>,
    state_store: SyncSignal<LocalStateStore>,
    connection_status: Signal<String>,
    last_error: Signal<Option<String>>,
    session_boot_state: Signal<SessionBootState>,
    secure_store_bootstrap_ready: Signal<bool>,
    is_server_admin: Signal<bool>,
    theme: Signal<String>,
    system_theme_is_night: Signal<bool>,
    children: Element,
) -> Element {
    rsx! {
        GlobalEffects {
            locale,
            i18n_signal,
            base_url,
            token,
            state_store,
            connection_status,
            last_error,
            session_boot_state,
            secure_store_bootstrap_ready,
            is_server_admin,
            theme,
            system_theme_is_night,
        }
        {children}
    }
}

/// Keeps the auth/app-shell boundary as one stable component node while only
/// mounting the active surface. The small conditional template here prevents
/// either surface's internal RSX from changing the parent template shape.
#[component]
pub(super) fn SessionSurface(
    is_app_shell: bool,
    auth_shell: Element,
    children: Element,
) -> Element {
    rsx! {
        if is_app_shell {
            {children}
        } else {
            {auth_shell}
        }
    }
}

/// Owns the complete mobile drawer template. Keeping the drawer root and its
/// primary links in one component prevents surrounding shell reconciliation
/// from moving those links outside the hidden navigation container.
#[component]
pub(super) fn MobileNavDrawer(
    mobile_nav_open: Signal<bool>,
    status: Element,
    realm_tree: Element,
) -> Element {
    rsx! {
        nav {
            id: "mobile-navigation-drawer",
            class: if mobile_nav_open() { "mobile-drawer open" } else { "mobile-drawer" },
            "data-testid": "mobile-nav-drawer",
            {status}
            div { class: "mobile-primary-nav",
                Link { class: "secondary", "data-testid": "mobile-dashboard-nav-button", to: Route::Dashboard, onclick: move |_| mobile_nav_open.set(false), {crate::i18n::tr("nav.dashboard")} }
                Link { class: "secondary", "data-testid": "mobile-file-transfer-nav-button", to: Route::FileTransfer, onclick: move |_| mobile_nav_open.set(false), {crate::i18n::tr("nav.files")} }
                Link { class: "secondary", "data-testid": "mobile-directory-nav-button", to: Route::Directory, onclick: move |_| mobile_nav_open.set(false), {crate::i18n::tr("nav.directory")} }
                Link { class: "secondary", "data-testid": "mobile-settings-nav-button", to: Route::Settings, onclick: move |_| mobile_nav_open.set(false), {crate::i18n::tr("nav.settings")} }
            }
            {realm_tree}
        }
    }
}
