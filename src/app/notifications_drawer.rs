use dioxus::prelude::*;
use dioxus_router::Link;

use crate::components::UiIcon;
use crate::routes::Route;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};

#[component]
pub(crate) fn NotificationsDrawer(
    mut open: Signal<bool>,
    principal_id: String,
    device_id: String,
    token: Signal<String>,
) -> Element {
    if !open() {
        return rsx! {};
    }

    rsx! {
        div {
            class: "notifications-drawer-layer",
            "data-testid": "notifications-drawer",
            aside {
                class: "notifications-drawer-panel",
                "data-testid": "notifications-drawer-panel",
                "aria-label": crate::i18n::tr("nav.notifications"),
                onclick: move |event: dioxus::events::MouseEvent| event.stop_propagation(),
                div { class: "notifications-drawer-header",
                    div { class: "notifications-drawer-title",
                        UiIcon { name: "bell" }
                        span { {crate::i18n::tr("nav.notifications")} }
                    }
                    div { class: "notifications-drawer-actions",
                        Link {
                            class: "btn icon sm ghost",
                            "data-testid": "notifications-drawer-settings",
                            title: crate::i18n::tr("notifications.tooltip.settings"),
                            "aria-label": crate::i18n::tr("notifications.tooltip.settings"),
                            to: Route::SettingsSection {
                                section: "notifications".to_owned(),
                                filter: String::new(),
                            },
                            onclick: move |_| open.set(false),
                            UiIcon { name: "settings" }
                        }
                        Button {
                            variant: ButtonVariant::Ghost,
                            size: ButtonSize::Sm,
                            r#type: "button",
                            class: "btn icon",
                            "data-testid": "notifications-drawer-close",
                            title: crate::i18n::tr("common.close"),
                            "aria-label": crate::i18n::tr("common.close"),
                            onclick: move |_| open.set(false),
                            UiIcon { name: "x" }
                        }
                    }
                }
                crate::views::notifications::NotificationsPanel {
                    principal_id,
                    device_id,
                    token,
                    on_open_chat: move |_| open.set(false),
                }
            }
        }
    }
}
