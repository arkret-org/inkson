//! Shared outside-click dismissal layer for modal-like popups.
//!
//! The popup closes only from a real `click` on the overlay. Press/release
//! events are intentionally ignored so dragging across the surface boundary
//! does not dismiss the popup.

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

    rsx! {
        div {
            class: "{overlay_class}",
            "data-testid": "{overlay_test_id}",
            style: "{overlay_style}",
            onclick: move |_| on_dismiss.call(()),
            div {
                class: "{surface_class}",
                "data-testid": "{surface_test_id}",
                style: "{surface_style}",
                role: "dialog",
                "aria-modal": "true",
                "aria-label": "{aria_label}",
                onclick: move |event: dioxus::events::MouseEvent| event.stop_propagation(),
                {children}
            }
        }
    }
}
