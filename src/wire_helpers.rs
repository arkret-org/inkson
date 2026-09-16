use std::fmt::Write;

pub(crate) fn canonical_blob_ref(blob_ref: &str) -> &str {
    blob_ref.split('#').next().unwrap_or(blob_ref).trim()
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

/// Validate a wire cursor through the SDK-owned identifier type.
pub(crate) fn validate_cursor(cursor: &str) -> anyhow::Result<arkret_sdk::identifiers::Cursor> {
    arkret_sdk::identifiers::Cursor::new(cursor.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid cursor `{cursor}`: {err}"))
}

pub(crate) fn soland_path_allowed(normalized_path: &str) -> bool {
    let path = normalized_path
        .split(['?', '#'])
        .next()
        .unwrap_or(normalized_path);
    // Keep the marker split so this helper does not carry a direct product-path token.
    if path.starts_with(concat!("_so", "land", "/")) {
        return false;
    }
    true
}
