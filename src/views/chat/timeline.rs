//! Semantic chat text and participant presentation.
use super::*;

pub(super) fn render_message_text_block(
    text: String,
    mentions: &[MentionNode],
    base_url: &str,
) -> View {
    let parts = mention_inline_parts(&text, mentions, base_url);
    let children = parts
        .into_iter()
        .map(|part| {
            let class = if part.mention_label.is_some() {
                if part.is_local {
                    "mention-token is-local message-event-mention"
                } else {
                    "mention-token is-remote message-event-mention"
                }
            } else {
                "message-text-part"
            };
            Box::new(glory::ui::text().class(class).content(part.text)) as View
        })
        .collect::<Vec<_>>();
    Box::new(view().class("content-block-text").fill(children))
}

pub(super) fn render_message_body(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    body: &str,
    format: Option<arkret_sdk::TextFormat>,
    mentions: &[MentionNode],
    base_url: &str,
) -> View {
    let blocks = crate::content::parse_message_body_with_format(body, format);
    if mentions.is_empty() {
        return crate::content::render_blocks(scope, context, &blocks);
    }
    let children = blocks
        .into_iter()
        .map(|block| match block {
            crate::content::ContentBlock::Text(text) => {
                render_message_text_block(text, mentions, base_url)
            }
            other => crate::content::render_blocks(scope, context.clone(), &[other]),
        })
        .collect();
    super::native::block("content-blocks", children)
}

pub(super) struct DiscussionParticipantRowProps {
    pub participant: SpaceParticipant,
    pub participants: Vec<SpaceParticipant>,
    pub display_label: String,
    pub nested_agent: bool,
    pub show_binding_details: bool,
}
pub(super) fn discussion_participant_row(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    props: DiscussionParticipantRowProps,
) -> View {
    use super::native::block;
    use crate::presentation::widgets::{line, paragraph, plain};
    let participant = props.participant;
    let id = participant.roster_key();
    let owner = agent_controller_label(&participant, &props.participants);
    let selector = agent_selector_label(&participant);
    let slug = participant
        .agent_metadata
        .as_ref()
        .map(|metadata| metadata.agent_slug.clone())
        .filter(|slug| !slug.trim().is_empty());
    let row_class = if participant.is_self {
        "contact-row participant-row self"
    } else if props.nested_agent {
        "contact-row participant-row participant-agent-row"
    } else if participant.is_agent {
        "contact-row participant-row agent"
    } else {
        "contact-row participant-row"
    };
    let avatar = crate::components::identity_avatar(
        scope,
        context.clone(),
        crate::components::IdentityAvatarProps {
            seed: id.clone(),
            alt_text: props.display_label.clone(),
            blob_ref: None,
            class: "avatar-img participant-avatar".into(),
            test_id: None,
        },
    );
    let identity = crate::components::actor_identity_label(
        scope,
        context.clone(),
        crate::components::ActorIdentityLabelProps {
            label: slug.clone().unwrap_or(props.display_label),
            title: Some(id.clone()),
            class: Some("mono participant-id".into()),
            is_self: participant.is_self,
            is_agent: participant.is_agent,
            agent_slug: slug,
            ..Default::default()
        },
    );
    let mut children = vec![identity];
    if let Some(owner) = owner {
        children.push(paragraph(
            "muted participant-agent-subline participant-agent-owner",
            format!("agent of {owner}"),
        ));
    }
    if let Some(selector) = selector.as_ref() {
        children.push(paragraph(
            "mono muted participant-agent-selector",
            format!("@{selector}"),
        ));
    }
    children.push(line(
        "participant-badges",
        vec![paragraph(
            "badge participant-badge member",
            participant.role.label().to_owned(),
        )],
    ));
    if props.show_binding_details {
        let mut details = vec![paragraph(
            "mono muted",
            short_protocol_id(participant.principal_id.as_str()),
        )];
        if let Some(selector) = selector {
            details.push(plain(format!("@{selector}")));
        }
        let details = Rc::new(std::cell::RefCell::new(Some(block(
            "binding-context-details-content",
            details,
        ))));
        children.push(Box::new(
            sapid::collapsible(format!("binding-{}", uuid_v7()))
                .unstyled()
                .class("binding-context-details")
                .content_policy(sapid::ContentPolicy::KeepMounted)
                .label(context.translated(scope, "chat.binding_context.details"))
                .content(move || {
                    details
                        .borrow_mut()
                        .take()
                        .unwrap_or_else(crate::presentation::widgets::empty)
                }),
        ));
    }
    line(row_class, vec![avatar, block("participant-main", children)])
}

pub(super) fn mention_nodes_to_values(mentions: &[MentionNode]) -> Vec<serde_json::Value> {
    mentions
        .iter()
        .filter_map(|mention| serde_json::to_value(mention).ok())
        .collect()
}
