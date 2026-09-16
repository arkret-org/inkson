use dioxus::prelude::*;
use dioxus_router::Link;

use super::UiIcon;
use crate::routes::Route;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::dialog::Dialog;

#[component]
pub fn DeviceAuthorizationPrompt(needs_device_authorization: Signal<bool>) -> Element {
    let mut dismissed = use_signal(|| false);

    use_effect(move || {
        if !needs_device_authorization() {
            dismissed.set(false);
        }
    });

    if !needs_device_authorization() {
        return rsx! {};
    }

    if dismissed() {
        return rsx! {
            Button {
                variant: ButtonVariant::Primary,
                size: ButtonSize::IconSm,
                r#type: "button",
                class: "btn mls-unlock-reopen-button",
                "data-testid": "device-authorization-reopen",
                title: crate::i18n::tr("device_authorization.reopen"),
                "aria-label": crate::i18n::tr("device_authorization.reopen"),
                onclick: move |_| dismissed.set(false),
                UiIcon { name: "unlock" }
            }
        };
    }

    rsx! {
        Dialog {
            open: true,
            on_open_change: move |open: bool| {
                if !open {
                    dismissed.set(true);
                }
            },
            "data-testid": "device-authorization-modal",
            "aria-labelledby": "device-authorization-title",
            div { class: "modal mls-recovery-modal device-authorization-dialog",
            div { class: "modal-head event-head",
                div {
                    h3 { id: "device-authorization-title", {crate::i18n::tr("device_authorization.title")} }
                    span { class: "muted", {crate::i18n::tr("device_authorization.subtitle")} }
                }
                Button {
                    variant: ButtonVariant::Ghost,
                    size: ButtonSize::IconSm,
                    r#type: "button",
                    class: "btn close",
                    "data-testid": "device-authorization-dismiss-icon",
                    title: crate::i18n::tr("device_authorization.dismiss"),
                    "aria-label": crate::i18n::tr("device_authorization.dismiss"),
                    onclick: move |_| dismissed.set(true),
                    UiIcon { name: "x" }
                }
            }
            div { class: "modal-body mls-recovery-modal-body",
                div { class: "muted",
                    {crate::i18n::tr("device_authorization.description")}
                }
                div {
                    class: "mls-device-authorization-details",
                    "data-testid": "device-authorization-path",
                    div {
                        class: "mls-device-authorization-path",
                        div {
                            class: "mls-device-authorization-step",
                            strong { {crate::i18n::tr("device_authorization.approve_step_existing_title")} }
                            span { {crate::i18n::tr("device_authorization.approve_step_existing_body")} }
                        }
                        div {
                            class: "mls-device-authorization-step",
                            strong { {crate::i18n::tr("device_authorization.approve_step_new_title")} }
                            span { {crate::i18n::tr("device_authorization.approve_step_new_body")} }
                        }
                    }
                }
                div { class: "mls-device-authorization-limitation",
                    UiIcon { name: "alert" }
                    span { {crate::i18n::tr("device_authorization.limitation")} }
                }
            }
            div { class: "modal-foot actions mls-unlock-row",
                Link {
                    class: "primary",
                    "data-testid": "device-authorization-open-pairing",
                    to: Route::SettingsDevicesPair,
                    onclick: move |_| dismissed.set(true),
                    {crate::i18n::tr("device_authorization.open_pairing")}
                }
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "device-authorization-dismiss",
                    onclick: move |_| dismissed.set(true),
                    {crate::i18n::tr("device_authorization.dismiss")}
                }
            }
            }
        }
    }
}
