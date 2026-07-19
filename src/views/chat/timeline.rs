//! Pure chat timeline projection and rendering components.

use dioxus::prelude::*;

use super::model::*;
use crate::components::{ActorIdentityLabel, UiIcon};
use crate::views::helpers::{MentionNode, short_protocol_id};

pub(super) fn push_unique_mention_node(mentions: &mut Vec<MentionNode>, mention: MentionNode) {
    if !mentions.iter().any(|existing| {
        existing.as_mention().is_some() == mention.as_mention().is_some()
            && existing.target_id() == mention.target_id()
    }) {
        mentions.push(mention);
    }
}

pub(super) fn render_message_text_block(
    key: String,
    text: String,
    mentions: Vec<MentionNode>,
    base_url: String,
) -> Element {
    let parts = mention_inline_parts(&text, &mentions, &base_url);
    rsx! {
        p {
            key: "{key}",
            class: "content-block-text",
            "data-testid": "content-block-text",
            for (idx, part) in parts.into_iter().enumerate() {
                {
                    let part_key = format!("{key}-part-{idx}");
                    if let Some(label) = part.mention_label {
                        let class = if part.is_local {
                            "mention-token is-local"
                        } else {
                            "mention-token is-remote"
                        };
                        rsx! {
                            span {
                                key: "{part_key}",
                                class: "{class}",
                                "data-testid": "message-event-mention",
                                title: "{label}",
                                "{part.text}"
                            }
                        }
                    } else {
                        rsx! {
                            span { key: "{part_key}", "{part.text}" }
                        }
                    }
                }
            }
        }
    }
}

pub(super) fn render_message_body(body: &str, mentions: &[MentionNode], base_url: &str) -> Element {
    let blocks = crate::content::parse_message_body(body);
    if mentions.is_empty() {
        return crate::content::render_blocks(&blocks);
    }

    let owned_mentions = mentions.to_vec();
    let base_url = base_url.to_owned();
    rsx! {
        div { class: "content-blocks", "data-testid": "content-blocks",
            for (idx, block) in blocks.into_iter().enumerate() {
                {
                    let key = format!("content-block-{idx}");
                    match block {
                        crate::content::ContentBlock::Text(text) => {
                            render_message_text_block(
                                key,
                                text,
                                owned_mentions.clone(),
                                base_url.clone(),
                            )
                        }
                        other => {
                            let single = vec![other];
                            rsx! {
                                div { key: "{key}",
                                    {crate::content::render_blocks(&single)}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
pub(super) fn DiscussionParticipantRow(
    participant: SpaceParticipant,
    participants: Vec<SpaceParticipant>,
    display_label: String,
    nested_agent: bool,
    show_binding_details: bool,
) -> Element {
    let participant_did_attr = participant.did.clone();
    let participant_did_label = short_protocol_id(&participant_did_attr);
    let binding_host = participant
        .did
        .strip_prefix("did:web:")
        .map(|rest| rest.split(':').next().unwrap_or(rest).to_owned());
    let owner_label = agent_controller_label(&participant, &participants);
    let selector_label = agent_selector_label(&participant);
    let agent_slug = participant
        .agent_metadata
        .as_ref()
        .map(|metadata| metadata.agent_slug.clone())
        .filter(|slug| !slug.trim().is_empty());
    let identity_label = agent_slug.clone().unwrap_or_else(|| display_label.clone());
    let controller_id_attr = participant
        .agent_metadata
        .as_ref()
        .map(|metadata| metadata.controller_id.clone())
        .unwrap_or_default();
    let row_class = if participant.is_self {
        "contact-row participant-row self"
    } else if nested_agent {
        "contact-row participant-row participant-agent-row"
    } else if participant.is_agent {
        "contact-row participant-row agent"
    } else {
        "contact-row participant-row"
    };
    let avatar_icon = if participant.is_agent { "bot" } else { "user" };

    rsx! {
        div {
            class: "{row_class}",
            "data-testid": if nested_agent { "discussion-agent-row" } else { "discussion-user-row" },
            "data-agent-controller-id": "{controller_id_attr}",
            span { class: "participant-avatar", UiIcon { name: avatar_icon.to_owned() } }
            div { class: "participant-main",
                strong {
                    ActorIdentityLabel {
                        label: identity_label,
                        title: Some(participant_did_attr.clone()),
                        class: Some("mono participant-did".to_owned()),
                        test_id: Some("participant".to_owned()),
                        self_badge_test_id: Some("participant-self-badge".to_owned()),
                        agent_badge_test_id: Some("member-badge-agent".to_owned()),
                        is_self: participant.is_self,
                        agent_slug,
                        agent_selector: None,
                    }
                    if !participant.is_agent {
                        if let Some(host) = binding_host.as_ref() {
                            span { class: "binding-context",
                                "data-testid": "binding-context",
                                {crate::i18n::tr("chat.binding_context.separator")}
                                span { class: "binding-context-host", "{host}" }
                            }
                        }
                    }
                }
                if let Some(owner) = owner_label.as_ref() {
                    div {
                        class: "muted participant-agent-subline",
                        "data-testid": "participant-agent-owner",
                        "agent of {owner}"
                    }
                }
                if let Some(selector) = selector_label.as_ref() {
                    div {
                        class: "mono muted participant-agent-selector",
                        "data-testid": "participant-agent-selector",
                        "@{selector}"
                    }
                }
                div { class: "participant-badges",
                    span {
                        class: "badge participant-badge member",
                        "{participant.role.label()}"
                    }
                }
                if show_binding_details {
                    details { class: "binding-context-details",
                        summary { class: "muted", {crate::i18n::tr("chat.binding_context.details")} }
                        div { class: "mono muted", title: "{participant_did_attr}",
                            "{participant_did_label}"
                        }
                        if let Some(selector) = selector_label.clone() {
                            div { class: "mono muted", "@{selector}" }
                        }
                    }
                }
            }
        }
    }
}

pub(super) fn mention_nodes_to_values(mentions: &[MentionNode]) -> Vec<serde_json::Value> {
    mentions
        .iter()
        .filter_map(|mention| serde_json::to_value(mention).ok())
        .collect()
}

pub(super) fn scroll_chat_feed_to_latest() {
    let script = r#"
setTimeout(() => {
  const panels = document.querySelectorAll('[data-testid="chat-panel"]');
  const panel = panels[panels.length - 1];
  const feed = panel && panel.querySelector('[data-testid="message-list"]');
  if (feed) {
    feed.scrollTop = feed.scrollHeight;
  }
}, 0);
"#;
    let _ = document::eval(script);
}
