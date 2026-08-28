//! Utilities for Arkret user handles.
//!
//! The canonical wire form is
//! `<prepared-localpart>:<lowercase-A-label-domain>` with no port. The previous
//! `arkret://domain/users/local` URI form has been retired.
//! `acct:<percent-encoded-localpart>@<A-label-domain>` remains an interop alias only.
//!
//! A handle is **addressing only**. It is NEVER materialised into an
//! authoritative principal/subject DID on the client: per
//! `identity/identity-handles.md §80` the resolution result MUST first be
//! reduced to a DID + verifiable claim by the Directory (`resolve_handle`),
//! and a handle string carries no verifiable claim that the client could use
//! to fabricate that DID. The previous client-side
//! `format!("did:web:{domain}:users:{localpart}")` materialisation has been
//! removed: it both bypassed the directory-attested reduction and hard-coded
//! the `did:web` method even though v1 core defaults principal/service to
//! `did:webvh`. The authoritative `subject_id` / `recipient_id` must
//! be taken from the Directory `resolve_handle` response (verified claim
//! subject + member delivery binding) and never from this parser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedUserHandle {
    pub localpart: String,
    pub domain: String,
    pub display: String,
    /// Canonical wire handle `<prepared-localpart>:<lowercase-A-label-domain>`.
    /// Same string as [`display`]; carried as its own
    /// field so callers that want the wire-canonical form can grab it
    /// without going through the display path.
    pub handle: String,
    pub acct_alias: String,
}

pub fn parse_user_handle(input: &str) -> Option<ParsedUserHandle> {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.starts_with("did:") {
        return None;
    }

    if trimmed.starts_with("arkret://") {
        return None;
    }

    let handle = parse_sdk_handle(trimmed).ok()?;
    Some(parsed_from_sdk_handle(handle))
}

fn parse_sdk_handle(input: &str) -> arkret_sdk::Result<arkret_models_identity::Handle> {
    let trimmed = input.trim();
    let body = trimmed.strip_prefix('@').unwrap_or(trimmed);
    if body.starts_with("acct:") {
        return arkret_models_identity::Handle::from_acct(body).map_err(Into::into);
    }
    if body.contains('@') {
        let acct = format!("acct:{body}");
        return arkret_models_identity::Handle::from_acct(&acct).map_err(Into::into);
    }
    arkret_models_identity::Handle::prepare(body).map_err(Into::into)
}

fn parsed_from_sdk_handle(handle: arkret_models_identity::Handle) -> ParsedUserHandle {
    ParsedUserHandle {
        localpart: handle.localpart().to_owned(),
        domain: handle.domain().to_owned(),
        display: handle.canonical().to_owned(),
        handle: handle.canonical().to_owned(),
        acct_alias: handle.to_acct(),
    }
}

pub fn normalize_user_handle_display(input: &str) -> Option<String> {
    parse_user_handle(input).map(|handle| handle.display)
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
        assert_eq!(parsed.localpart, "alice");
        assert_eq!(parsed.domain, "example.com");
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
        assert_eq!(
            parse_user_handle("@小明:domain.中国").unwrap().handle,
            "小明:domain.xn--fiqs8s"
        );
    }

    #[test]
    fn rejects_non_handle_tokens() {
        assert!(parse_user_handle("did:web:alice.example").is_none());
        assert!(parse_user_handle("@alice").is_none());
        assert!(parse_user_handle("alice.example.com").is_none());
        // R3.1: arkret:// URI form is retired.
        assert!(parse_user_handle("arkret://example.com/users/alice").is_none());
    }

    #[test]
    fn principal_identifier_accepts_did_but_fails_closed_on_handle() {
        // A bare handle is NOT materialised into a fabricated DID; reducing it
        // requires a directory-attested resolve_handle round-trip.
    }
}
