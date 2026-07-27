use std::time::Duration;

use dioxus::prelude::*;
use yoface::utils::dom::copy_text_to_clipboard;

use super::UiIcon;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::textarea::Textarea;

/// Shared QR + URL handoff surface used by invites, device pairing, and Agent
/// runtime pairing. The QR is the primary cross-device action; the readable,
/// copyable URL is the universal fallback.
#[component]
pub fn QrSharePanel(
    qr_svg: String,
    url: String,
    qr_aria_label: String,
    url_aria_label: String,
    qr_test_id: String,
    url_test_id: String,
    copy_test_id: String,
    #[props(default = 4)] url_rows: u32,
) -> Element {
    let mut copied = use_signal(|| false);
    let mut copy_epoch = use_signal(|| 0_u64);

    rsx! {
        div { class: "qr-share-container",
        div { class: "qr-share-panel",
            div { class: "qr-share-qr-pane",
                strong { class: "qr-share-pane-label", {crate::i18n::tr("qr_share.scan")} }
                if qr_svg.is_empty() {
                    div { class: "muted qr-share-empty", {crate::i18n::tr("qr_share.unavailable")} }
                } else {
                    div {
                        class: "qr-image qr-share-image",
                        "data-testid": "{qr_test_id}",
                        role: "img",
                        "aria-label": "{qr_aria_label}",
                        dangerous_inner_html: "{qr_svg}",
                    }
                }
            }
            div { class: "qr-share-url-pane",
                div { class: "qr-share-url-head",
                    strong { class: "qr-share-pane-label", {crate::i18n::tr("qr_share.use_link")} }
                    Button {
                        variant: ButtonVariant::Secondary,
                        size: ButtonSize::Sm,
                        class: if copied() { "btn qr-share-copy success" } else { "btn qr-share-copy" },
                        "data-testid": "{copy_test_id}",
                        disabled: url.is_empty(),
                        onclick: {
                            let value = url.clone();
                            move |_| {
                                copy_text_to_clipboard(&value);
                                let epoch = copy_epoch().wrapping_add(1);
                                copy_epoch.set(epoch);
                                copied.set(true);
                                spawn(async move {
                                    crate::runtime_helpers::sleep_for(Duration::from_millis(2_000))
                                        .await;
                                    let is_latest = copy_epoch
                                        .try_read()
                                        .map(|current| *current == epoch)
                                        .unwrap_or(false);
                                    if is_latest && let Ok(mut state) = copied.try_write() {
                                        *state = false;
                                    }
                                });
                            }
                        },
                        if copied() {
                            UiIcon { name: "check" }
                            span { "aria-live": "polite", {crate::i18n::tr("qr_share.copied")} }
                        } else {
                            UiIcon { name: "copy" }
                            span { {crate::i18n::tr("qr_share.copy_link")} }
                        }
                    }
                }
                Textarea {
                    class: "mono qr-share-url-field",
                    "data-testid": "{url_test_id}",
                    "aria-label": "{url_aria_label}",
                    title: "{url}",
                    readonly: true,
                    rows: "{url_rows}",
                    value: "{url}",
                }
                span { class: "muted qr-share-hint", {crate::i18n::tr("qr_share.private_hint")} }
            }
        }
        }
    }
}
