use std::time::Duration;

use dioxus::prelude::*;
use dioxus_primitives::dialog::{self, DialogDescriptionProps, DialogRootProps, DialogTitleProps};
use dioxus_primitives::dioxus_attributes::attributes;
use dioxus_primitives::merge_attributes;

#[css_module("/src/ui/dialog/style.css")]
struct Styles;

#[component]
pub fn Dialog(props: DialogRootProps) -> Element {
    let mut suppress_backdrop_click = use_signal(|| false);
    let base = attributes!(div {
        class: Styles::dx_dialog,
        role: "dialog",
        "aria-modal": "true",
    });
    let merged = merge_attributes(vec![base, props.attributes]);
    let open = (props.open)().unwrap_or(props.default_open);

    if !open {
        return rsx! {};
    }

    rsx! {
        div {
            class: Styles::dx_dialog_backdrop,
            id: props.id,
            "data-state": "open",
            onclick: move |_| {
                if suppress_backdrop_click() {
                    suppress_backdrop_click.set(false);
                    return;
                }
                props.on_open_change.call(false);
            },
            onmouseup: move |_| {
                if !suppress_backdrop_click() {
                    return;
                }
                let mut suppress_backdrop_click = suppress_backdrop_click;
                spawn(async move {
                    crate::api::sleep_for(Duration::from_millis(32)).await;
                    if suppress_backdrop_click() {
                        suppress_backdrop_click.set(false);
                    }
                });
            },
            div {
                onmousedown: move |event: dioxus::events::MouseEvent| {
                    suppress_backdrop_click.set(true);
                    event.stop_propagation();
                },
                onmouseup: move |_| {
                    suppress_backdrop_click.set(false);
                },
                onclick: move |event: dioxus::events::MouseEvent| {
                    suppress_backdrop_click.set(false);
                    event.stop_propagation();
                },
                ..merged,
                {props.children}
            }
        }
    }
}

#[component]
pub fn DialogTitle(props: DialogTitleProps) -> Element {
    let base = attributes!(h2 {
        class: Styles::dx_dialog_title,
    });
    let merged = merge_attributes(vec![base, props.attributes]);

    rsx! {
        dialog::DialogTitle {
            id: props.id,
            attributes: merged,
            {props.children}
        }
    }
}

#[component]
pub fn DialogDescription(props: DialogDescriptionProps) -> Element {
    let base = attributes!(p {
        class: Styles::dx_dialog_description,
    });
    let merged = merge_attributes(vec![base, props.attributes]);

    rsx! {
        dialog::DialogDescription {
            id: props.id,
            attributes: merged,
            {props.children}
        }
    }
}
