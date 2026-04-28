use dioxus::prelude::*;

#[derive(Clone, Debug, PartialEq)]
enum BlockKind {
    Paragraph,
    Heading,
    BulletList,
    CodeBlock,
}

#[derive(Clone, Debug, PartialEq)]
struct DocumentBlock {
    id: String,
    kind: BlockKind,
    content: String,
}

#[derive(Clone, Debug, PartialEq)]
struct DocumentVersion {
    id: String,
    timestamp: String,
    author: String,
    block_count: usize,
}

#[component]
pub fn DocumentPanel(
    base_url: String,
    token: Signal<String>,
    selected_space: String,
) -> Element {
    let mut blocks = use_signal(|| {
        vec![
            DocumentBlock {
                id: "block-1".to_owned(),
                kind: BlockKind::Heading,
                content: "Untitled Document".to_owned(),
            },
            DocumentBlock {
                id: "block-2".to_owned(),
                kind: BlockKind::Paragraph,
                content: "Start writing here...".to_owned(),
            },
        ]
    });
    let mut versions = use_signal(|| {
        vec![DocumentVersion {
            id: "v-1".to_owned(),
            timestamp: chrono::Utc::now().format("%Y-%m-%d %H:%M").to_string(),
            author: "clientx".to_owned(),
            block_count: 2,
        }]
    });
    let mut editing_block = use_signal(|| Option::<String>::None);
    let mut edit_text = use_signal(String::new);
    let mut show_versions = use_signal(|| false);

    rsx! {
        div { class: "timeline", "data-testid": "document-panel",
            // Document header
            div { class: "event",
                div { class: "event-head",
                    span { "Document" }
                    span { "{selected_space}" }
                }
                div { class: "actions",
                    button {
                        class: if !show_versions() { "primary" } else { "secondary" },
                        onclick: move |_| show_versions.set(false),
                        "Edit"
                    }
                    button {
                        class: if show_versions() { "primary" } else { "secondary" },
                        onclick: move |_| show_versions.set(true),
                        "History ({versions().len()})"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "save-document",
                        onclick: move |_| {
                            let v_count = versions().len();
                            let b_count = blocks().len();
                            versions.write().push(DocumentVersion {
                                id: format!("v-{v_count}"),
                                timestamp: "2026-01-01 00:00".to_owned(),
                                author: "clientx".to_owned(),
                                block_count: b_count,
                            });
                        },
                        "Save Version"
                    }
                }
            }

            if show_versions() {
                // Version history
                div { class: "event", "data-testid": "version-history",
                    div { class: "event-head", span { "Version History" } span { "{versions().len()} versions" } }
                    for version in versions() {
                        div { class: "event", "data-testid": "version-entry",
                            div { class: "event-head",
                                span { "{version.id}" }
                                span { "{version.timestamp}" }
                            }
                            div { class: "muted", "By: {version.author} ({version.block_count} blocks)" }
                        }
                    }
                }
            } else {
                // Block editor
                for (idx, block) in blocks().iter().enumerate() {
                    div {
                        class: "event",
                        "data-testid": "document-block",
                        div { class: "event-head",
                            span { match block.kind {
                                BlockKind::Paragraph => "paragraph",
                                BlockKind::Heading => "heading",
                                BlockKind::BulletList => "list",
                                BlockKind::CodeBlock => "code",
                            }}
                            span { "block {idx}" }
                        }

                        if editing_block() == Some(block.id.clone()) {
                            textarea {
                                "data-testid": "block-edit-input",
                                value: "{edit_text}",
                                oninput: move |evt| edit_text.set(evt.value()),
                                style: "width: 100%; min-height: 60px;",
                            }
                            div { class: "actions",
                                button {
                                    class: "primary",
                                    onclick: move |_| {
                                        let text = edit_text().trim().to_owned();
                                        if !text.is_empty() {
                                            if let Some(b) = blocks.write().iter_mut().find(|b| b.id == editing_block().unwrap_or_default()) {
                                                b.content = text;
                                            }
                                        }
                                        editing_block.set(None);
                                        edit_text.set(String::new());
                                    },
                                    "Save"
                                }
                                button {
                                    class: "secondary",
                                    onclick: move |_| { editing_block.set(None); edit_text.set(String::new()); },
                                    "Cancel"
                                }
                            }
                        } else {
                            div {
                                onclick: {
                                    let bid = block.id.clone();
                                    let content = block.content.clone();
                                    move |_| {
                                        editing_block.set(Some(bid.clone()));
                                        edit_text.set(content.clone());
                                    }
                                },
                                style: "cursor: text; padding: 8px 0;",
                                match block.kind {
                                    BlockKind::Heading => rsx! { h2 { style: "margin: 0;", "{block.content}" } },
                                    BlockKind::BulletList => rsx! { ul { li { "{block.content}" } } },
                                    BlockKind::CodeBlock => rsx! { pre { code { "{block.content}" } } },
                                    BlockKind::Paragraph => rsx! { p { style: "margin: 0;", "{block.content}" } },
                                }
                            }
                        }

                        // Block type change
                        div { class: "actions",
                            button {
                                class: "secondary",
                                onclick: {
                                    let bid = block.id.clone();
                                    move |_| {
                                        if let Some(b) = blocks.write().iter_mut().find(|b| b.id == bid) {
                                            b.kind = BlockKind::Paragraph;
                                        }
                                    }
                                },
                                "P"
                            }
                            button {
                                class: "secondary",
                                onclick: {
                                    let bid = block.id.clone();
                                    move |_| {
                                        if let Some(b) = blocks.write().iter_mut().find(|b| b.id == bid) {
                                            b.kind = BlockKind::Heading;
                                        }
                                    }
                                },
                                "H"
                            }
                            button {
                                class: "secondary",
                                onclick: {
                                    let bid = block.id.clone();
                                    move |_| {
                                        if let Some(b) = blocks.write().iter_mut().find(|b| b.id == bid) {
                                            b.kind = BlockKind::BulletList;
                                        }
                                    }
                                },
                                "L"
                            }
                            button {
                                class: "secondary",
                                onclick: {
                                    let bid = block.id.clone();
                                    move |_| {
                                        if let Some(b) = blocks.write().iter_mut().find(|b| b.id == bid) {
                                            b.kind = BlockKind::CodeBlock;
                                        }
                                    }
                                },
                                "</>"
                            }
                            button {
                                class: "secondary",
                                onclick: {
                                    let bid = block.id.clone();
                                    move |_| blocks.write().retain(|b| b.id != bid)
                                },
                                "Delete"
                            }
                        }
                    }
                }

                // Add block button
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "add-block-button",
                        onclick: move |_| {
                            blocks.write().push(DocumentBlock {
                                id: format!("block-{}", chrono::Utc::now().timestamp_millis()),
                                kind: BlockKind::Paragraph,
                                content: String::new(),
                            });
                        },
                        "+ Add Block"
                    }
                }
            }
        }
    }
}
