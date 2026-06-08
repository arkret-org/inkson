//! Create-Circle modal (CKP-0007 / P3B.2.6).
//!
//! Surfaced from the Realm-detail page header. Collects the minimum
//! Circle fields (title, short_name, color, symbol, directory
//! visibility, initial members) and on submit emits the canonical
//! `ck.circle.create` envelope shape via the parent's `on_submit`
//! handler.
//!
//! Member-set validation enforces the CKP-0007 strict-subset invariant
//! client-side: every entered DID must also appear in `realm_members`.
//! Strict-subset failures render inline before the user can submit; the
//! reducer also enforces the same rule (reason
//! `circle_member_must_be_realm_member`).

use dioxus::prelude::*;

use crate::ui::button::{Button, ButtonVariant};
use crate::ui::dialog::Dialog;
use crate::ui::input::Input;
use crate::ui::select::{Select, SelectOption};
use crate::ui::textarea::Textarea;

/// Form payload emitted by the modal on submit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CircleCreateForm {
    pub title: String,
    pub short_name: String,
    pub color_token: String,
    pub symbol_glyph: String,
    pub directory_visibility: String,
    pub initial_members: Vec<String>,
}

/// Strict-subset check, exposed for unit tests. Returns the first DID
/// that violates the invariant, otherwise `Ok(())`.
pub fn validate_strict_subset(
    circle_members: &[String],
    realm_members: &[String],
) -> Result<(), String> {
    let realm: std::collections::BTreeSet<&str> =
        realm_members.iter().map(String::as_str).collect();
    for member in circle_members {
        if !realm.contains(member.as_str()) {
            return Err(member.clone());
        }
    }
    Ok(())
}

#[component]
pub fn CreateCircleModal(
    realm_id: String,
    realm_members: Vec<String>,
    on_submit: EventHandler<CircleCreateForm>,
    on_cancel: EventHandler<()>,
) -> Element {
    let mut form = use_signal(CircleCreateForm::default);
    let mut members_text = use_signal(String::new);
    let mut validation_error = use_signal(|| Option::<String>::None);

    let color_token_selected = use_memo(move || Some(form.read().color_token.clone()));
    let symbol_glyph_selected = use_memo(move || Some(form.read().symbol_glyph.clone()));
    let directory_visibility_selected =
        use_memo(move || Some(form.read().directory_visibility.clone()));

    rsx! {
        Dialog {
            open: true,
            on_open_change: move |open: bool| {
                if !open {
                    on_cancel.call(());
                }
            },
            "data-testid": "create-circle-modal",
            "aria-label": "New Circle in {realm_id}",
            div { class: "modal create-circle-modal-overlay",
                header { class: "modal-head",
                    h2 { "New Circle in {realm_id}" }
                    Button {
                        variant: ButtonVariant::Secondary,
                        class: "icon-only",
                        "data-testid": "create-circle-cancel",
                        "aria-label": "Cancel and close dialog",
                        onclick: move |_| on_cancel.call(()),
                        "×"
                    }
                }
                div { class: "modal-body",
                    label { class: "field",
                        span { class: "field-label", "Title" }
                        Input {
                            class: "input",
                            "data-testid": "create-circle-title",
                            value: "{form.read().title}",
                            oninput: move |event: FormEvent| {
                                let value = event.value();
                                form.with_mut(|f| f.title = value);
                            },
                        }
                    }
                    label { class: "field",
                        span { class: "field-label", "Short name" }
                        Input {
                            class: "input",
                            "data-testid": "create-circle-short-name",
                            value: "{form.read().short_name}",
                            oninput: move |event: FormEvent| {
                                let value = event.value();
                                form.with_mut(|f| f.short_name = value);
                            },
                        }
                    }
                    label { class: "field",
                        span { class: "field-label", "Color token" }
                        Select::<String> {
                            class: "select",
                            "data-testid": "create-circle-color",
                            value: Some(color_token_selected.into()),
                            on_value_change: move |v: Option<String>| {
                                if let Some(v) = v {
                                    form.with_mut(|f| f.color_token = v);
                                }
                            },
                            for (i, token) in ["slate", "indigo", "violet", "emerald", "amber", "pink", "cyan"].iter().enumerate() {
                                SelectOption::<String> { index: i, value: token.to_string(), text_value: "{token}", "{token}" }
                            }
                        }
                    }
                    label { class: "field",
                        span { class: "field-label", "Symbol glyph" }
                        Select::<String> {
                            class: "select",
                            "data-testid": "create-circle-symbol",
                            value: Some(symbol_glyph_selected.into()),
                            on_value_change: move |v: Option<String>| {
                                if let Some(v) = v {
                                    form.with_mut(|f| f.symbol_glyph = v);
                                }
                            },
                            for (i, glyph) in [
                                "lock", "shield", "eye", "eye_off", "user_shield", "fingerprint",
                                "key", "diamond", "flame", "leaf", "anchor", "compass", "atom",
                                "bolt", "moon", "sun", "star", "globe", "satellite", "ring", "chain",
                                "tag", "flag", "scroll", "scale", "hourglass", "spark",
                            ].iter().enumerate() {
                                SelectOption::<String> { index: i, value: glyph.to_string(), text_value: "{glyph}", "{glyph}" }
                            }
                        }
                    }
                    label { class: "field",
                        span { class: "field-label", "Directory visibility" }
                        Select::<String> {
                            class: "select",
                            "data-testid": "create-circle-visibility",
                            value: Some(directory_visibility_selected.into()),
                            on_value_change: move |v: Option<String>| {
                                if let Some(v) = v {
                                    form.with_mut(|f| f.directory_visibility = v);
                                }
                            },
                            SelectOption::<String> { index: 0usize, value: "members".to_string(), text_value: "Members only", "Members only" }
                            SelectOption::<String> { index: 1usize, value: "realm_members".to_string(), text_value: "Realm members", "Realm members" }
                        }
                    }
                    label { class: "field",
                        span { class: "field-label", "Initial members (one DID per line — strict subset of Realm)" }
                        Textarea {
                            class: "textarea",
                            "data-testid": "create-circle-members",
                            rows: "5",
                            value: "{members_text.read()}",
                            oninput: move |event: FormEvent| {
                                members_text.set(event.value());
                            },
                        }
                    }
                    if let Some(err) = validation_error.read().as_ref() {
                        p {
                            class: "field-error",
                            "data-testid": "create-circle-validation-error",
                            "Strict-subset violation: {err} is not an active Realm member."
                        }
                    }
                }
                footer { class: "modal-foot",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "create-circle-cancel-bottom",
                        "aria-label": "Cancel new Circle",
                        onclick: move |_| on_cancel.call(()),
                        "Cancel"
                    }
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "create-circle-submit",
                        "aria-label": "Create new Circle",
                        onclick: move |_| {
                            let members: Vec<String> = members_text
                                .read()
                                .lines()
                                .map(|line| line.trim().to_owned())
                                .filter(|line| !line.is_empty())
                                .collect();
                            match validate_strict_subset(&members, &realm_members) {
                                Ok(()) => {
                                    validation_error.set(None);
                                    let mut payload = form.read().clone();
                                    payload.initial_members = members;
                                    on_submit.call(payload);
                                }
                                Err(offender) => {
                                    validation_error.set(Some(offender));
                                }
                            }
                        },
                        "Create Circle"
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_subset_accepts_subset() {
        let realm = vec!["did:web:alice".to_owned(), "did:web:bob".to_owned()];
        validate_strict_subset(&["did:web:alice".to_owned()], &realm).unwrap();
    }

    #[test]
    fn strict_subset_rejects_outsider() {
        let realm = vec!["did:web:alice".to_owned()];
        let err = validate_strict_subset(&["did:web:eve".to_owned()], &realm).unwrap_err();
        assert_eq!(err, "did:web:eve");
    }

    #[test]
    fn empty_members_is_valid() {
        validate_strict_subset(&[], &["did:web:alice".to_owned()]).unwrap();
    }
}
