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
            is_server_admin,
            theme,
            system_theme_is_night,
        }
        {children}
    }
}
