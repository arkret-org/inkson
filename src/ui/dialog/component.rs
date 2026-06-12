use dioxus::prelude::*;
use dioxus_primitives::dialog::{self, DialogDescriptionProps, DialogRootProps, DialogTitleProps};
use dioxus_primitives::dioxus_attributes::attributes;
use dioxus_primitives::merge_attributes;

#[css_module("/src/ui/dialog/style.css")]
struct Styles;

#[component]
pub fn Dialog(props: DialogRootProps) -> Element {
    let mut surface_press_started = use_signal(|| false);
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
                if surface_press_started() {
                    surface_press_started.set(false);
                    return;
                }
                props.on_open_change.call(false);
            },
            div {
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
