use dioxus::prelude::*;

use crate::views::helpers::authed_api;

#[derive(Clone, Debug, PartialEq)]
struct SocialPost {
    id: String,
    author: String,
    content: String,
    audience: String,
    media_refs: Vec<String>,
    likes: usize,
    timestamp: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FeedFilter {
    All,
    Contacts,
    Circle,
    Topic,
}

#[component]
pub fn SocialFeedPanel(
    base_url: String,
    token: Signal<String>,
) -> Element {
    let mut posts = use_signal(|| {
        vec![SocialPost {
            id: "post-1".to_owned(),
            author: "clientx".to_owned(),
            content: "Welcome to the social feed! This is a dev-mode post.".to_owned(),
            audience: "public".to_owned(),
            media_refs: Vec::new(),
            likes: 0,
            timestamp: chrono::Utc::now().format("%Y-%m-%d %H:%M").to_string(),
        }]
    });
    let mut composer_text = use_signal(String::new);
    let mut audience = use_signal(|| "public".to_owned());
    let mut filter = use_signal(|| FeedFilter::All);
    let status_msg = use_signal(|| String::new());
    let mut media_status = use_signal(|| String::new());

    rsx! {
        div { class: "timeline", "data-testid": "social-feed-panel",
            // Post composer
            div { class: "event", "data-testid": "post-composer",
                div { class: "event-head", span { "Compose" } span { "new post" } }
                div { class: "composer",
                    textarea {
                        "data-testid": "post-input",
                        value: "{composer_text}",
                        placeholder: "What's on your mind?",
                        oninput: move |evt| composer_text.set(evt.value()),
                    }
                    // Audience selector
                    div { class: "actions",
                        span { class: "muted", "Audience:" }
                        button {
                            class: if audience() == "public" { "primary" } else { "secondary" },
                            onclick: move |_| audience.set("public".to_owned()),
                            "Public"
                        }
                        button {
                            class: if audience() == "contacts" { "primary" } else { "secondary" },
                            onclick: move |_| audience.set("contacts".to_owned()),
                            "Contacts"
                        }
                        button {
                            class: if audience() == "circle" { "primary" } else { "secondary" },
                            onclick: move |_| audience.set("circle".to_owned()),
                            "Circle"
                        }
                    }
                    // Media attach
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "attach-media-button",
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let base = base.clone();
                                    let api_token = token();
                                    spawn(async move {
                                        if let Ok(api) = authed_api(&base, api_token) {
                                            match api.upload_blob(b"clientx social media blob").await {
                                                Ok(blob) => media_status.set(format!("attached {}", blob.blob_ref)),
                                                Err(e) => media_status.set(format!("attach failed: {e}")),
                                            }
                                        }
                                    });
                                }
                            },
                            "Attach Media"
                        }
                        if !media_status().is_empty() {
                            span { class: "muted", "{media_status}" }
                        }
                    }
                    // Post button
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "publish-post-button",
                            onclick: move |_| {
                                let content = composer_text().trim().to_owned();
                                if content.is_empty() {
                                    return;
                                }
                                posts.write().insert(0, SocialPost {
                                    id: format!("post-{}", chrono::Utc::now().timestamp_millis()),
                                    author: "clientx".to_owned(),
                                    content: content.clone(),
                                    audience: audience(),
                                    media_refs: Vec::new(),
                                    likes: 0,
                                    timestamp: chrono::Utc::now().format("%Y-%m-%d %H:%M").to_string(),
                                });
                                composer_text.set(String::new());
                                media_status.set(String::new());
                            },
                            "Publish"
                        }
                    }
                }
            }

            // Feed filter
            div { class: "event", "data-testid": "feed-filter",
                div { class: "actions",
                    button {
                        class: if filter() == FeedFilter::All { "primary" } else { "secondary" },
                        onclick: move |_| filter.set(FeedFilter::All),
                        "All"
                    }
                    button {
                        class: if filter() == FeedFilter::Contacts { "primary" } else { "secondary" },
                        onclick: move |_| filter.set(FeedFilter::Contacts),
                        "Contacts"
                    }
                    button {
                        class: if filter() == FeedFilter::Circle { "primary" } else { "secondary" },
                        onclick: move |_| filter.set(FeedFilter::Circle),
                        "Circle"
                    }
                    button {
                        class: if filter() == FeedFilter::Topic { "primary" } else { "secondary" },
                        onclick: move |_| filter.set(FeedFilter::Topic),
                        "Topic"
                    }
                }
            }

            // Feed
            for post in posts() {
                div { class: "event", "data-testid": "social-post",
                    div { class: "event-head",
                        span { "{post.author}" }
                        span { "{post.audience} / {post.timestamp}" }
                    }
                    div { "{post.content}" }
                    if !post.media_refs.is_empty() {
                        div { class: "muted", "Media: {post.media_refs:?}" }
                    }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "like-post-button",
                            onclick: move |_| {
                                if let Some(p) = posts.write().iter_mut().find(|p| p.id == post.id) {
                                    p.likes += 1;
                                }
                            },
                            "\u{2764}\u{fe0f} {post.likes}"
                        }
                    }
                }
            }

            if posts().is_empty() {
                div { class: "event",
                    div { class: "event-head", span { "Feed" } span { "empty" } }
                    div { class: "muted", "No posts yet. Compose one above!" }
                }
            }

            if !status_msg().is_empty() {
                div { class: "muted", "data-testid": "feed-status", "{status_msg}" }
            }
        }
    }
}
