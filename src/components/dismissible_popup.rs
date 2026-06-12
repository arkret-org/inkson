//! Shared outside-click dismissal layer for modal-like popups.
//!
//! The popup closes from a real overlay `click`, except when the press started
//! inside the surface and was dragged outside before release.

use dioxus::prelude::*;

#[derive(Clone, PartialEq, Props)]
pub struct DismissiblePopupProps {
    pub overlay_class: String,
    pub surface_class: String,
    pub aria_label: String,
    pub on_dismiss: EventHandler<()>,
    pub children: Element,
    #[props(default)]
    pub overlay_test_id: Option<String>,
    #[props(default)]
    pub surface_test_id: Option<String>,
    #[props(default)]
    pub overlay_style: Option<String>,
    #[props(default)]
    pub surface_style: Option<String>,
}

#[component]
pub fn DismissiblePopup(props: DismissiblePopupProps) -> Element {
    let DismissiblePopupProps {
        overlay_class,
        surface_class,
        aria_label,
        on_dismiss,
        children,
        overlay_test_id,
        surface_test_id,
        overlay_style,
        surface_style,
    } = props;
    let overlay_test_id = overlay_test_id.unwrap_or_default();
    let surface_test_id = surface_test_id.unwrap_or_default();
    let overlay_style = overlay_style.unwrap_or_default();
    let surface_style = surface_style.unwrap_or_default();
    let mut surface_press_started = use_signal(|| false);

    rsx! {
        div {
            class: "{overlay_class}",
            "data-testid": "{overlay_test_id}",
            style: "{overlay_style}",
            onclick: move |_| {
                if surface_press_started() {
                    surface_press_started.set(false);
                    return;
                }
                on_dismiss.call(());
            },
            div {
                class: "{surface_class}",
                "data-testid": "{surface_test_id}",
                style: "{surface_style}",
                role: "dialog",
                "aria-modal": "true",
                "aria-label": "{aria_label}",
                onmousedown: move |event: dioxus::events::MouseEvent| {
                    surface_press_started.set(true);
                    event.stop_propagation();
                },
                onmouseup: move |_| {
                    surface_press_started.set(false);
                },
                onclick: move |event: dioxus::events::MouseEvent| {
                    surface_press_started.set(false);
                    event.stop_propagation();
                },
                {children}
            }
        }
    }
}
