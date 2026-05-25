//! Account switcher dropdown (P3B.4.2).
//!
//! Lives in the topbar avatar slot. Lists every profile in the
//! [`crate::config::MultiProfileConfig`] and lets the user switch
//! active profile or jump into onboarding for a new one.
//!
//! Switching the active profile fires the `on_switch` handler with the
//! target `profile_id`; the parent (`app.rs`) is responsible for
//! persisting the new active id and notifying `sync_engine`.
//!
//! `TODO(circle-rollout-P3B.4.3):` once the sync engine listens for
//! profile-switch events, route the active-cursor / push-registration /
//! coauth-grant swap through a single `ProfileSwitchEvent` so neither
//! the UI shell nor the API layer have to peek into each subsystem.

use dioxus::prelude::*;

use crate::config::{AccountProfile, MultiProfileConfig};

#[component]
pub fn AccountSwitcher(
    profiles: MultiProfileConfig,
    on_switch: EventHandler<String>,
    on_add_account: EventHandler<()>,
    on_remove: EventHandler<String>,
) -> Element {
    let mut open = use_signal(|| false);
    let active_id = profiles.active_profile_id.clone();
    let active_label = profiles
        .active()
        .map(AccountProfile::display_label)
        .unwrap_or("Sign in")
        .to_owned();

    rsx! {
        div {
            class: "account-switcher",
            "data-testid": "account-switcher",
            button {
                class: "account-switcher-trigger",
                "data-testid": "account-switcher-trigger",
                onclick: move |_| open.toggle(),
                span { class: "avatar", "👤" }
                span { class: "account-label", "{active_label}" }
                span { class: "muted", "▾" }
            }
            if open() {
                div { class: "account-switcher-menu",
                    "data-testid": "account-switcher-menu",
                    ul { class: "account-list",
                        for profile in profiles.profiles.iter() {
                            {
                                let pid = profile.profile_id.clone();
                                let pid_for_switch = pid.clone();
                                let pid_for_remove = pid.clone();
                                let did = profile.account_did.clone();
                                let label = profile.display_label().to_owned();
                                let is_active = Some(pid.as_str()) == active_id.as_deref();
                                rsx! {
                                    li {
                                        key: "{pid}",
                                        class: if is_active { "account-row active" } else { "account-row" },
                                        "data-testid": "account-switcher-row",
                                        "data-profile-id": "{pid}",
                                        button {
                                            class: "account-row-switch",
                                            disabled: is_active,
                                            onclick: move |_| {
                                                on_switch.call(pid_for_switch.clone());
                                                open.set(false);
                                            },
                                            span { class: "account-row-label", "{label}" }
                                            span { class: "muted", "{did}" }
                                        }
                                        if !is_active {
                                            button {
                                                class: "icon-only",
                                                "data-testid": "account-switcher-remove",
                                                onclick: move |_| on_remove.call(pid_for_remove.clone()),
                                                "×"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    button {
                        class: "account-add-button",
                        "data-testid": "account-switcher-add",
                        onclick: move |_| {
                            on_add_account.call(());
                            open.set(false);
                        },
                        "+ Add another account"
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::AccountProfile;

    #[test]
    fn display_label_falls_back_to_did_segment() {
        let profile = AccountProfile::new(
            "https://contrix.example",
            "did:web:alice.example",
            "cx:device:01964137-0000-7000-8000-000000000099",
            "token",
        );
        assert_eq!(profile.display_label(), "alice.example");
    }

    #[test]
    fn display_label_prefers_explicit_label() {
        let mut profile = AccountProfile::new(
            "https://contrix.example",
            "did:web:alice.example",
            "cx:device:01964137-0000-7000-8000-000000000098",
            "token",
        );
        profile.label = "Work".to_owned();
        assert_eq!(profile.display_label(), "Work");
    }
}
