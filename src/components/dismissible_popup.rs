//! Shared outside-click dismissal layer for modal-like popups.
//!
//! Browser `click` retargeting can close an overlay when the pointer starts
//! inside the popup and is released on the backdrop. This component only calls
//! `on_dismiss` when both press and release happen on the backdrop itself.

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
    let mut backdrop_press_started = use_signal(|| false);
    let mut backdrop_press_ended = use_signal(|| false);
    let overlay_test_id = overlay_test_id.unwrap_or_default();
    let surface_test_id = surface_test_id.unwrap_or_default();
    let overlay_style = overlay_style.unwrap_or_default();
    let surface_style = surface_style.unwrap_or_default();

    rsx! {
        div {
            class: "{overlay_class}",
            "data-testid": "{overlay_test_id}",
            style: "{overlay_style}",
            onmousedown: move |_| {
                backdrop_press_started.set(true);
                backdrop_press_ended.set(false);
            },
            onmouseup: move |_| {
                backdrop_press_ended.set(true);
            },
            onclick: move |_| {
                if backdrop_press_started() && backdrop_press_ended() {
                    on_dismiss.call(());
                }
                backdrop_press_started.set(false);
                backdrop_press_ended.set(false);
            },
            div {
                class: "{surface_class}",
                "data-testid": "{surface_test_id}",
                style: "{surface_style}",
                role: "dialog",
                "aria-modal": "true",
                "aria-label": "{aria_label}",
                onmousedown: move |event: dioxus::events::MouseEvent| {
                    backdrop_press_started.set(false);
                    backdrop_press_ended.set(false);
                    event.stop_propagation();
                },
                onmouseup: move |event: dioxus::events::MouseEvent| {
                    backdrop_press_ended.set(false);
                    event.stop_propagation();
                },
                onclick: move |event: dioxus::events::MouseEvent| event.stop_propagation(),
                {children}
            }
        }
    }
}
