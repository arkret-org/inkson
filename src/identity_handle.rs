//! Utilities for Cokret user handles.
//!
//! R3.1 wire form (cokret-spec @ 7157ee8): the canonical handle is
//! `<localpart>:<domain>(:<port>)?`. The previous `cokret://domain/users/local`
//! URI form has been retired. `acct:<localpart>@<domain>` remains an interop
//! alias only.
//!
//! Realm membership materialises the resolved user DID plus the recipient
//! Principal Server DID, never the display string itself.
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedUserHandle {
    pub localpart: String,
    pub domain: String,
    pub port: Option<u16>,
    pub display: String,
    /// R3.1 canonical wire handle `<localpart>:<domain>(:<port>)?`.
    /// Same string as [`display`] for ASCII handles; carried as its own
    /// field so callers that want the wire-canonical form can grab it
    /// without going through the display path.
    pub handle: String,
    pub acct_alias: String,
    pub subject_did: String,
    pub principal_server_did: String,
}

pub fn parse_user_handle(input: &str) -> Option<ParsedUserHandle> {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.starts_with("did:") {
        return None;
    }

    if trimmed.starts_with("cokret://") {
        return None;
    }

    let handle = parse_sdk_handle(trimmed).ok()?;
    Some(parsed_from_sdk_handle(handle))
}

fn parse_sdk_handle(input: &str) -> cokret_sdk::Result<cokret_sdk::models::Handle> {
    let trimmed = input.trim();
    let body = trimmed.strip_prefix('@').unwrap_or(trimmed);
    if body.starts_with("acct:") {
        return cokret_sdk::models::Handle::from_acct(body);
    }
    if body.contains('@') {
        let acct = format!("acct:{body}");
        return cokret_sdk::models::Handle::from_acct(&acct);
    }
    cokret_sdk::models::Handle::parse(body)
}

fn parsed_from_sdk_handle(handle: cokret_sdk::models::Handle) -> ParsedUserHandle {
    let did_authority = if let Some(port) = handle.port() {
        format!("{}%3A{port}", handle.domain())
    } else {
        handle.domain().to_owned()
    };
    let principal_server_did = format!("did:web:{did_authority}");
    let subject_did = format!("{principal_server_did}:users:{}", handle.localpart());
    ParsedUserHandle {
        localpart: handle.localpart().to_owned(),
        domain: handle.domain().to_owned(),
        port: handle.port(),
        display: handle.canonical().to_owned(),
        handle: handle.canonical().to_owned(),
        acct_alias: handle.to_acct(),
        subject_did,
        principal_server_did,
    }
}

pub fn normalize_user_handle_display(input: &str) -> Option<String> {
    parse_user_handle(input).map(|handle| handle.display)
}

pub fn principal_did_from_identifier(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.starts_with("did:") && trimmed.len() > "did:".len() {
        return Some(trimmed.to_owned());
    }
    parse_user_handle(trimmed).map(|handle| handle.subject_did)
}

/// Client-side wrapper around the SDK's canonical localpart normalizer.
pub fn detect_handle_homograph_risk(localpart: &str) -> Option<HandleHomographRisk> {
    cokret_sdk::models::normalize_handle_localpart(localpart)
        .is_err()
        .then_some(HandleHomographRisk)
}

/// Marker returned when the SDK rejects a candidate localpart as unsafe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandleHomographRisk;

impl HandleHomographRisk {
    /// Human-readable label for the inline warning.
    pub fn script_label(&self) -> String {
        "confusable localpart".to_owned()
    }
}

/// Returns `true` when the input is not already NFC-normalized.
pub fn handle_will_be_nfc_normalised(localpart: &str) -> bool {
    localpart.nfc().ne(localpart.chars())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_display_handle_to_protocol_parts() {
        let parsed = parse_user_handle("Alice:Example.COM").expect("handle");
        assert_eq!(parsed.display, "alice:example.com");
        assert_eq!(parsed.handle, "alice:example.com");
        assert_eq!(parsed.acct_alias, "acct:alice@example.com");
        assert_eq!(parsed.principal_server_did, "did:web:example.com");
        assert_eq!(parsed.subject_did, "did:web:example.com:users:alice");
    }

    #[test]
    fn accepts_mention_and_acct_alias_inputs() {
        assert_eq!(
            parse_user_handle("@alice:example.com").unwrap().handle,
            "alice:example.com"
        );
        assert_eq!(
            parse_user_handle("alice@example.com").unwrap().handle,
            "alice:example.com"
        );
        assert_eq!(
            parse_user_handle("acct:alice@example.com").unwrap().display,
            "alice:example.com"
        );
    }

    #[test]
    fn rejects_non_handle_tokens() {
        assert!(parse_user_handle("did:web:alice.example").is_none());
        assert!(parse_user_handle("@alice").is_none());
        assert!(parse_user_handle("alice.example.com").is_none());
        // R3.1: cokret:// URI form is retired.
        assert!(parse_user_handle("cokret://example.com/users/alice").is_none());
    }

    #[test]
    fn pure_ascii_handle_has_no_homograph_risk() {
        assert!(detect_handle_homograph_risk("alice").is_none());
        assert!(detect_handle_homograph_risk("a.b_c+d~e-f").is_none());
        assert!(detect_handle_homograph_risk("123abc").is_none());
    }

    #[test]
    fn latin_plus_cyrillic_is_flagged() {
        // 'е' is U+0435 Cyrillic small letter ie.
        let risk = detect_handle_homograph_risk("alicе").expect("flagged");
        assert_eq!(risk.script_label(), "confusable localpart");
    }

    #[test]
    fn latin_plus_greek_is_flagged() {
        // 'α' is U+03B1 Greek small letter alpha.
        let risk = detect_handle_homograph_risk("aliceα").expect("flagged");
        assert_eq!(risk.script_label(), "confusable localpart");
    }

    #[test]
    fn pure_cyrillic_is_rejected_by_sdk_normalizer() {
        assert!(detect_handle_homograph_risk("алиса").is_some());
    }

    #[test]
    fn nfc_check_flags_combining_marks() {
        // 'e' + combining acute accent (U+0301) is NFD; NFC would be
        // 'é' (U+00E9). The decomposed form is what the helper detects.
        assert!(handle_will_be_nfc_normalised("e\u{0301}"));
        assert!(!handle_will_be_nfc_normalised("alice"));
    }

    #[test]
    fn principal_identifier_accepts_did_or_handle() {
        assert_eq!(
            principal_did_from_identifier("did:web:alice.example").unwrap(),
            "did:web:alice.example"
        );
        assert_eq!(
            principal_did_from_identifier("alice:example.com").unwrap(),
            "did:web:example.com:users:alice"
        );
    }
}
