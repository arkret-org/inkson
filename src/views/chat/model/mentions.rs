use super::*;

/// R3.2 §3.8.2 (YG-MENT-2) — resolve the *current* display label for a
/// structured actor mention via the shared SDK `render_mention()` helper.
///
/// The authoritative `target` (principal `subject_id`) drives §3.2.1
/// primary-handle selection. `handle_at_time` / `display_name_at_time`
/// are audit metadata and feed ONLY the degraded fallback ladder — they
/// are NEVER used as the current display value directly.
///
/// `TODO(R3.2.1)`: feed the Realm-scoped roster handle-claim snapshot +
/// accepted_issuers + a locally cached verified handle in here. Until the
/// live claim cache + `list_handles_for_subject` plumbing lands we pass an
/// empty snapshot, so the renderer steps down to the cached/name/DID
/// fallback ladder (each visually degraded) instead of inventing a
/// handle.
pub(crate) fn mention_label_from_node(mention: &MentionNode) -> Option<String> {
    if let Some(audience_mention) = mention.as_audience_mention() {
        return audience_mention
            .mention_text_original
            .as_deref()
            .and_then(|token| token.strip_prefix('@'))
            .filter(|label| !label.is_empty())
            .map(ToOwned::to_owned)
            .or_else(|| Some(audience_mention.audience.as_wire().to_owned()));
    }
    let mention = mention.as_mention()?;
    let display_name = mention.display_name_at_time.as_deref();
    let rendered = crate::views::helpers::render_actor_mention(
        mention.subject_id.as_str(),
        &[],  // claim_set_snapshot — TODO(R3.2.1) roster handle-claim evidence
        &[],  // accepted_issuers — TODO(R3.2.1) Realm policy
        None, // context (target Realm id)
        None, // cached verified handle — TODO(R3.2.1) local cache
        display_name,
    );
    // The verified / cached tiers render `@{localpart}:{domain}`; strip
    // the leading `@` to match the inline label shape used by the chat
    // renderer (which adds its own `@` styling). Name-only / unresolved
    // tiers return the bare name / truncated DID.
    Some(
        rendered
            .label
            .strip_prefix('@')
            .unwrap_or(&rendered.label)
            .to_owned(),
    )
}

pub(crate) fn local_server_domain(base_url: &str) -> Option<String> {
    url::Url::parse(base_url)
        .ok()
        .and_then(|url| url.host_str().map(|host| host.to_ascii_lowercase()))
}

pub(crate) fn handle_domain(label: &str) -> Option<String> {
    crate::identity::handle::parse_user_handle(label).map(|handle| handle.domain)
}

pub(crate) fn is_local_handle_label(label: &str, base_url: &str) -> bool {
    let Some(handle_domain) = handle_domain(label) else {
        return false;
    };
    let Some(server_domain) = local_server_domain(base_url) else {
        return false;
    };
    handle_domain == server_domain
        || server_domain.ends_with(&format!(".{handle_domain}"))
        || handle_domain.ends_with(&format!(".{server_domain}"))
}

pub(crate) fn normalize_account_handle(account_handle: &str) -> Option<String> {
    mention_handle_label_from_value(account_handle.trim().trim_start_matches('@').trim())
}

pub(crate) fn is_leading_mention_punct(ch: char) -> bool {
    matches!(ch, '(' | '[' | '{' | '"' | '\'')
}

pub(crate) fn is_trailing_mention_punct(ch: char) -> bool {
    matches!(
        ch,
        ',' | '.' | '!' | '?' | ';' | ')' | ']' | '}' | '"' | '\''
    )
}

pub(crate) fn token_core_bounds(token: &str) -> (usize, usize) {
    let start = token
        .char_indices()
        .find(|(_, ch)| !is_leading_mention_punct(*ch))
        .map(|(idx, _)| idx)
        .unwrap_or(token.len());
    let end = token
        .char_indices()
        .rev()
        .find(|(idx, ch)| *idx >= start && !is_trailing_mention_punct(*ch))
        .map(|(idx, ch)| idx + ch.len_utf8())
        .unwrap_or(start);
    (start, end)
}

pub(crate) fn split_preserving_whitespace(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut current_is_whitespace: Option<bool> = None;

    for ch in text.chars() {
        let is_whitespace = ch.is_whitespace();
        if let Some(previous) = current_is_whitespace
            && previous != is_whitespace
        {
            parts.push(std::mem::take(&mut current));
        }
        current_is_whitespace = Some(is_whitespace);
        current.push(ch);
    }

    if !current.is_empty() {
        parts.push(current);
    }

    parts
}

pub(crate) fn mention_inline_parts(
    text: &str,
    mentions: &[MentionNode],
    base_url: &str,
) -> Vec<MentionInlinePart> {
    let labels: std::collections::BTreeSet<String> = mentions
        .iter()
        .filter_map(mention_label_from_node)
        .collect();
    if labels.is_empty() {
        return vec![MentionInlinePart {
            text: text.to_owned(),
            mention_label: None,
            is_local: false,
        }];
    }

    let mut parts = Vec::new();
    for segment in split_preserving_whitespace(text) {
        if segment.chars().all(char::is_whitespace) {
            parts.push(MentionInlinePart {
                text: segment,
                mention_label: None,
                is_local: false,
            });
            continue;
        }

        let (core_start, core_end) = token_core_bounds(&segment);
        let core = &segment[core_start..core_end];
        let parsed_label = core
            .strip_prefix('@')
            .and_then(mention_handle_label_from_value);
        let Some(label) = parsed_label.filter(|label| labels.contains(label)) else {
            parts.push(MentionInlinePart {
                text: segment,
                mention_label: None,
                is_local: false,
            });
            continue;
        };

        let prefix = &segment[..core_start];
        if !prefix.is_empty() {
            parts.push(MentionInlinePart {
                text: prefix.to_owned(),
                mention_label: None,
                is_local: false,
            });
        }
        let mention_text = format!("@{label}");
        parts.push(MentionInlinePart {
            text: mention_text,
            is_local: is_local_handle_label(&label, base_url),
            mention_label: Some(label),
        });
        let suffix = &segment[core_end..];
        if !suffix.is_empty() {
            parts.push(MentionInlinePart {
                text: suffix.to_owned(),
                mention_label: None,
                is_local: false,
            });
        }
    }
    parts
}
