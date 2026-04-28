use dioxus::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemoryLayer {
    Working,
    Episodic,
    Semantic,
    Task,
}

#[derive(Clone, Debug, PartialEq)]
struct MemoryEntry {
    id: String,
    layer: MemoryLayer,
    content: String,
    confidence: f64,
    source: String,
    timestamp: String,
    reviewed: bool,
}

#[component]
pub fn MemoryReviewPanel(base_url: String, token: Signal<String>) -> Element {
    let mut memories = use_signal(|| {
        vec![
            MemoryEntry {
                id: "mem-1".to_owned(),
                layer: MemoryLayer::Working,
                content: "User is currently reviewing the memory panel".to_owned(),
                confidence: 0.95,
                source: "session".to_owned(),
                timestamp: "2026-01-01 00:00".to_owned(),
                reviewed: false,
            },
            MemoryEntry {
                id: "mem-2".to_owned(),
                layer: MemoryLayer::Semantic,
                content: "Contrix uses DID-based identity for authentication".to_owned(),
                confidence: 0.99,
                source: "documentation".to_owned(),
                timestamp: "2026-01-01 00:00".to_owned(),
                reviewed: false,
            },
        ]
    });
    let mut filter_layer = use_signal(|| Option::<MemoryLayer>::None);
    let mut edit_id = use_signal(|| Option::<String>::None);
    let mut edit_text = use_signal(String::new);

    let filtered: Vec<MemoryEntry> = memories()
        .iter()
        .filter(|m| filter_layer().map_or(true, |layer| m.layer == layer))
        .cloned()
        .collect();
    let filtered_empty = filtered.is_empty();

    rsx! {
        div { class: "timeline", "data-testid": "memory-review-panel",
            div { class: "event",
                div { class: "event-head", span { "Memory Review" } span { "agent memories" } }
                div { class: "muted", "Review, edit, or reject agent memory entries." }
            }

            // Layer filter
            div { class: "event", "data-testid": "memory-filter",
                div { class: "actions",
                    button {
                        class: if filter_layer().is_none() { "primary" } else { "secondary" },
                        onclick: move |_| filter_layer.set(None),
                        "All"
                    }
                    button {
                        class: if filter_layer() == Some(MemoryLayer::Working) { "primary" } else { "secondary" },
                        onclick: move |_| filter_layer.set(Some(MemoryLayer::Working)),
                        "Working"
                    }
                    button {
                        class: if filter_layer() == Some(MemoryLayer::Episodic) { "primary" } else { "secondary" },
                        onclick: move |_| filter_layer.set(Some(MemoryLayer::Episodic)),
                        "Episodic"
                    }
                    button {
                        class: if filter_layer() == Some(MemoryLayer::Semantic) { "primary" } else { "secondary" },
                        onclick: move |_| filter_layer.set(Some(MemoryLayer::Semantic)),
                        "Semantic"
                    }
                    button {
                        class: if filter_layer() == Some(MemoryLayer::Task) { "primary" } else { "secondary" },
                        onclick: move |_| filter_layer.set(Some(MemoryLayer::Task)),
                        "Task"
                    }
                }
            }

            // Memory entries
            for memory in filtered {
                div {
                    class: "event",
                    "data-testid": "memory-entry",
                    style: if memory.reviewed { "opacity: 0.6;" } else { "" },
                    div { class: "event-head",
                        span { match memory.layer {
                            MemoryLayer::Working => "working",
                            MemoryLayer::Episodic => "episodic",
                            MemoryLayer::Semantic => "semantic",
                            MemoryLayer::Task => "task",
                        }}
                        span { "{memory.source}" }
                    }
                    div { class: "space-title", "{memory.content}" }
                    div { class: "muted", "Confidence: {(memory.confidence * 100.0) as u32}%" }
                    div { class: "muted", "Created: {memory.timestamp}" }

                    if edit_id() == Some(memory.id.clone()) {
                        div { class: "workflow-form",
                            textarea {
                                "data-testid": "memory-edit-input",
                                value: "{edit_text}",
                                oninput: move |evt| edit_text.set(evt.value()),
                            }
                            div { class: "actions",
                                button {
                                    class: "primary",
                                    "data-testid": "save-memory-edit",
                                    onclick: move |_| {
                                        let text = edit_text().trim().to_owned();
                                        if !text.is_empty() {
                                            if let Some(m) = memories.write().iter_mut().find(|m| m.id == edit_id().unwrap_or_default()) {
                                                m.content = text;
                                            }
                                        }
                                        edit_id.set(None);
                                        edit_text.set(String::new());
                                    },
                                    "Save"
                                }
                                button {
                                    class: "secondary",
                                    onclick: move |_| { edit_id.set(None); edit_text.set(String::new()); },
                                    "Cancel"
                                }
                            }
                        }
                    } else {
                        div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "accept-memory-button",
                                onclick: {
                                    let mid = memory.id.clone();
                                    move |_| {
                                        if let Some(m) = memories.write().iter_mut().find(|m| m.id == mid) {
                                            m.reviewed = true;
                                        }
                                    }
                                },
                                "Accept"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "edit-memory-button",
                                onclick: {
                                    let mid = memory.id.clone();
                                    let content = memory.content.clone();
                                    move |_| {
                                        edit_id.set(Some(mid.clone()));
                                        edit_text.set(content.clone());
                                    }
                                },
                                "Edit"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "reject-memory-button",
                                onclick: {
                                    let mid = memory.id.clone();
                                    move |_| memories.write().retain(|m| m.id != mid)
                                },
                                "Reject"
                            }
                        }
                    }
                }
            }

            if filtered_empty {
                div { class: "event",
                    div { class: "event-head", span { "Memory" } span { "empty" } }
                    div { class: "muted", "No memory entries match the current filter." }
                }
            }
        }
    }
}
