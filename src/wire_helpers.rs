use std::fmt::Write;

/// A4b — module-level helper for composing a blob download URL when an API
/// handle isn't available (e.g. read-only views that already have the Principal
/// Server `base_url` as a string). Keeps the URL shape canonical so callers
/// cannot accidentally desync from the API method.
pub fn blob_download_url_for(base_url: &str, blob_ref: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let blob_ref = query_component(canonical_blob_ref(blob_ref));
    format!("{base}/_cokret/self/blob/get?blob_ref={blob_ref}&purpose=profile_avatar")
}

pub(crate) fn canonical_blob_ref(blob_ref: &str) -> &str {
    blob_ref.split('#').next().unwrap_or(blob_ref).trim()
}

pub(crate) fn query_component(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

pub(crate) fn path_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(&mut encoded, "%{byte:02X}");
        }
    }
    encoded
}

pub(crate) fn safe_blob_filename_header(filename: &str) -> Option<String> {
    let basename = filename
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .trim()
        .trim_matches('"');
    let mut sanitized = String::new();
    for ch in basename.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
            sanitized.push(ch);
        } else if ch.is_ascii_whitespace() || ch.is_ascii_punctuation() {
            sanitized.push('_');
        }
        if sanitized.len() >= 128 {
            break;
        }
    }
    let sanitized = sanitized
        .trim_matches(|ch| matches!(ch, '.' | '_' | '-' | ' '))
        .to_owned();
    (!sanitized.is_empty()).then_some(sanitized)
}

/// H3 — central guard for the `ck:cursor:*` prefix invariant. Every yougen
/// entry point that takes a cursor / `next_cursor` / `after` query argument
/// passes it through this helper before going on the wire. The nil-initial
/// account subscribe case (`after: None`) is handled by callers using
/// `Option::map` so this never runs against an `""` placeholder.
pub(crate) fn validate_cursor(cursor: &str) -> anyhow::Result<()> {
    if cursor.is_empty() {
        return Ok(());
    }
    if !cursor.starts_with("ck:cursor:") {
        anyhow::bail!("cursor must start with `ck:cursor:` (got `{}`)", cursor);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn events_query_path(realm_id: &str) -> String {
    format!(
        "_cokret/self/events?realms={}&limit=100",
        query_component(realm_id)
    )
}

// Builds the legacy `ck.self.events.stream.subscribe` URL. Kept only for URL
// construction regression tests; production realm subscribe now goes through
// SDK http-client + client-core.
#[cfg(test)]
pub(crate) fn events_subscribe_path(
    realm_id: &str,
    after: Option<&str>,
    include_history: Option<bool>,
    max_duration_ms: Option<u64>,
) -> String {
    let mut url = format!(
        "_cokret/self/events/subscribe?realms={}",
        query_component(realm_id)
    );
    if let Some(after) = after {
        url.push_str("&after=");
        url.push_str(&query_component(after));
    }
    if let Some(include_history) = include_history {
        url.push_str("&include_history=");
        url.push_str(if include_history { "true" } else { "false" });
    }
    if let Some(max_duration_ms) = max_duration_ms {
        url.push_str("&max_duration_ms=");
        url.push_str(&max_duration_ms.to_string());
    }
    url
}
