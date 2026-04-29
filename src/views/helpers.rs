use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    api::ContrixApi,
    config::{ClientConfig, LocalConfigStore},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredMention {
    pub kind: String,
    pub target: String,
    pub token: String,
}

/// Create an authenticated API client from a base URL and optional access token.
pub fn authed_api(base_url: &str, access_token: String) -> anyhow::Result<ContrixApi> {
    authed_api_with_sync(base_url, access_token, None)
}

/// Create an authenticated API client that also forwards the latest sync token
/// for read-your-writes consistency on subsequent reads.
pub fn authed_api_with_sync(
    base_url: &str,
    access_token: String,
    wait_for_sync_token: Option<String>,
) -> anyhow::Result<ContrixApi> {
    let mut api = ContrixApi::new(base_url)?;
    if !access_token.is_empty() {
        api = api.with_bearer(access_token);
    }
    if let Some(sync_token) = wait_for_sync_token {
        api = api.with_wait_for(sync_token);
    }
    Ok(api)
}

/// Derive a lowercase handle string from a DID, suitable for registration.
pub fn handle_from_did(did: &str) -> String {
    did.rsplit(':')
        .next()
        .unwrap_or("chask")
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

/// Persist the current client configuration (server URL, DID, device ID, token).
pub fn persist_config(
    mut config_store: Signal<LocalConfigStore>,
    server_url: String,
    account_did: String,
    device_id: String,
    session_token: String,
) {
    config_store.write().save(ClientConfig::from_fields(
        server_url,
        account_did,
        device_id,
        session_token,
    ));
}

pub fn active_sync_token(sync_cursor: &str) -> Option<String> {
    (!sync_cursor.trim().is_empty() && sync_cursor != "-").then(|| sync_cursor.to_owned())
}

pub fn parse_structured_mentions(input: &str) -> Vec<StructuredMention> {
    let mut mentions = Vec::new();
    for token in input.split_whitespace() {
        let normalized = token.trim_matches(|ch: char| {
            matches!(
                ch,
                ',' | '.' | '!' | '?' | ':' | ';' | ')' | '(' | '[' | ']' | '"' | '\''
            )
        });
        if let Some(actor) = normalized.strip_prefix("@did:") {
            mentions.push(StructuredMention {
                kind: "actor".to_owned(),
                target: format!("did:{actor}"),
                token: normalized.to_owned(),
            });
            continue;
        }
        if let Some(handle) = normalized.strip_prefix('@') {
            if !handle.is_empty() {
                mentions.push(StructuredMention {
                    kind: "actor".to_owned(),
                    target: format!("did:web:{handle}"),
                    token: normalized.to_owned(),
                });
            }
            continue;
        }
        if let Some(entity) = normalized.strip_prefix("#cx:") {
            mentions.push(StructuredMention {
                kind: "entity".to_owned(),
                target: format!("cx:{entity}"),
                token: normalized.to_owned(),
            });
            continue;
        }
        if let Some(entity) = normalized.strip_prefix('#') {
            if !entity.is_empty() {
                mentions.push(StructuredMention {
                    kind: "entity".to_owned(),
                    target: entity.to_owned(),
                    token: normalized.to_owned(),
                });
            }
        }
    }

    mentions.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then(left.token.cmp(&right.token))
    });
    mentions.dedup_by(|left, right| left.kind == right.kind && left.target == right.target);
    mentions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_actor_and_entity_mentions() {
        let mentions = parse_structured_mentions(
            "ping @did:web:bob.example and @carol.example about #cx:task:123 and #topic-demo",
        );

        assert_eq!(mentions.len(), 4);
        assert!(
            mentions
                .iter()
                .any(|mention| mention.target == "did:web:bob.example")
        );
        assert!(
            mentions
                .iter()
                .any(|mention| mention.target == "did:web:carol.example")
        );
        assert!(
            mentions
                .iter()
                .any(|mention| mention.target == "cx:task:123")
        );
        assert!(
            mentions
                .iter()
                .any(|mention| mention.target == "topic-demo")
        );
    }
}
