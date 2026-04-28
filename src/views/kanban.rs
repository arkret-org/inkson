use dioxus::prelude::*;

#[derive(Clone, Debug, PartialEq)]
struct KanbanColumn {
    id: String,
    title: String,
    cards: Vec<KanbanCard>,
}

#[derive(Clone, Debug, PartialEq)]
struct KanbanCard {
    id: String,
    title: String,
    description: String,
}

#[component]
pub fn KanbanPanel(base_url: String, token: Signal<String>, selected_space: String) -> Element {
    let mut columns = use_signal(|| {
        vec![
            KanbanColumn {
                id: "col-todo".to_owned(),
                title: "To Do".to_owned(),
                cards: vec![KanbanCard {
                    id: "card-1".to_owned(),
                    title: "Example task".to_owned(),
                    description: "A sample card for the kanban board".to_owned(),
                }],
            },
            KanbanColumn {
                id: "col-progress".to_owned(),
                title: "In Progress".to_owned(),
                cards: Vec::new(),
            },
            KanbanColumn {
                id: "col-done".to_owned(),
                title: "Done".to_owned(),
                cards: Vec::new(),
            },
        ]
    });
    let mut new_column_title = use_signal(String::new);
    let mut new_card_title = use_signal(String::new);
    let mut adding_card_to = use_signal(|| Option::<String>::None);
    let mut selected_card = use_signal(|| Option::<KanbanCard>::None);

    rsx! {
        div { class: "timeline", "data-testid": "kanban-panel",
            // Board header
            div { class: "event",
                div { class: "event-head",
                    span { "Kanban Board" }
                    span { "{selected_space}" }
                }
                div { class: "workflow-form",
                    div { class: "actions",
                        input {
                            "data-testid": "new-column-input",
                            value: "{new_column_title}",
                            placeholder: "New column title",
                            oninput: move |evt| new_column_title.set(evt.value()),
                        }
                        button {
                            class: "secondary",
                            "data-testid": "add-column-button",
                            onclick: move |_| {
                                let title = new_column_title().trim().to_owned();
                                if !title.is_empty() {
                                    let col_count = columns().len();
                                    columns.write().push(KanbanColumn {
                                        id: format!("col-{col_count}"),
                                        title: title.clone(),
                                        cards: Vec::new(),
                                    });
                                    new_column_title.set(String::new());
                                }
                            },
                            "Add Column"
                        }
                    }
                }
            }

            // Columns
            div {
                style: "display: flex; gap: 16px; overflow-x: auto; padding: 8px 0;",
                for (_col_idx, column) in columns().iter().enumerate() {
                    div {
                        class: "event",
                        "data-testid": "kanban-column",
                        style: "min-width: 240px; max-width: 300px;",
                        div { class: "event-head",
                            span { class: "space-title", "{column.title}" }
                            span { "{column.cards.len()}" }
                        }

                        // Cards
                        for card in &column.cards {
                            div {
                                class: "event",
                                "data-testid": "kanban-card",
                                style: "cursor: pointer;",
                                onclick: {
                                    let c = card.clone();
                                    move |_| selected_card.set(Some(c.clone()))
                                },
                                div { class: "space-title", "{card.title}" }
                                div { class: "muted", "{card.description}" }
                            }
                        }

                        // Add card
                        if adding_card_to() == Some(column.id.clone()) {
                            div { class: "workflow-form",
                                input {
                                    "data-testid": "new-card-title-input",
                                    value: "{new_card_title}",
                                    placeholder: "Card title",
                                    oninput: move |evt| new_card_title.set(evt.value()),
                                }
                                div { class: "actions",
                                    button {
                                        class: "primary",
                                        "data-testid": "save-card-button",
                                        onclick: {
                                            let col_id = column.id.clone();
                                            move |_| {
                                                let title = new_card_title().trim().to_owned();
                                                if !title.is_empty() {
                                                    if let Some(col) = columns.write().iter_mut().find(|c| c.id == col_id) {
                                                        col.cards.push(KanbanCard {
                                                            id: format!("card-{}", chrono::Utc::now().timestamp_millis()),
                                                            title: title,
                                                            description: String::new(),
                                                        });
                                                    }
                                                    new_card_title.set(String::new());
                                                    adding_card_to.set(None);
                                                }
                                            }
                                        },
                                        "Add"
                                    }
                                    button {
                                        class: "secondary",
                                        onclick: move |_| adding_card_to.set(None),
                                        "Cancel"
                                    }
                                }
                            }
                        } else {
                            div { class: "actions",
                                button {
                                    class: "secondary",
                                    "data-testid": "add-card-button",
                                    onclick: {
                                        let col_id = column.id.clone();
                                        move |_| adding_card_to.set(Some(col_id.clone()))
                                    },
                                    "+ Add Card"
                                }
                            }
                        }

                        // Remove column button
                        div { class: "actions",
                            button {
                                class: "secondary",
                                "data-testid": "remove-column-button",
                                onclick: {
                                    let col_id = column.id.clone();
                                    move |_| columns.write().retain(|c| c.id != col_id)
                                },
                                "Remove Column"
                            }
                        }
                    }
                }
            }

            // Card detail modal
            if let Some(ref card) = selected_card() {
                div { class: "event", "data-testid": "card-detail-modal",
                    div { class: "event-head",
                        span { "Card Detail" }
                        span { "{card.id}" }
                    }
                    div { class: "space-title", "{card.title}" }
                    div { class: "muted", "{card.description}" }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            onclick: move |_| selected_card.set(None),
                            "Close"
                        }
                    }
                }
            }
        }
    }
}
