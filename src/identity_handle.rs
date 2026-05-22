/// Utilities for Contrix user handles.
///
/// Protocol display input is `user:domain.example` (optionally with a
/// leading `@` in mention-style surfaces). The signed / cached protocol
/// form is always `contrix://domain.example/users/user`; Realm membership
/// materialises the resolved user DID plus the recipient Principal Server
/// DID, never the display string itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedUserHandle {
    pub localpart: String,
    pub domain: String,
    pub port: Option<u16>,
    pub display: String,
    pub handle_uri: String,
    pub acct_alias: String,
    pub subject_did: String,
    pub principal_server_did: String,
}

pub fn parse_user_handle(input: &str) -> Option<ParsedUserHandle> {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.starts_with("did:") {
        return None;
    }

    if trimmed.starts_with("contrix://") {
        return parse_handle_uri(trimmed);
    }

    let without_acct = trimmed.strip_prefix("acct:").unwrap_or(trimmed);
    let without_at_prefix = without_acct.strip_prefix('@').unwrap_or(without_acct);

    let (local, authority) = if let Some((local, authority)) = without_at_prefix.rsplit_once('@') {
        (local, authority)
    } else {
        without_at_prefix.split_once(':')?
    };
    build_handle(local, authority)
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

fn parse_handle_uri(input: &str) -> Option<ParsedUserHandle> {
    let rest = input.strip_prefix("contrix://")?;
    let (authority, local) = rest.split_once("/users/")?;
    if local.contains('/') {
        return None;
    }
    build_handle(local, authority)
}

fn build_handle(local: &str, authority: &str) -> Option<ParsedUserHandle> {
    let localpart = local.trim().to_ascii_lowercase();
    if !valid_localpart(&localpart) {
        return None;
    }

    let authority = authority.trim().to_ascii_lowercase();
    let (domain, port) = split_authority(&authority)?;
    if !valid_domain(&domain) {
        return None;
    }

    let display = match port {
        Some(port) => format!("{localpart}:{domain}:{port}"),
        None => format!("{localpart}:{domain}"),
    };
    let handle_uri = match port {
        Some(port) => format!("contrix://{domain}:{port}/users/{localpart}"),
        None => format!("contrix://{domain}/users/{localpart}"),
    };
    let acct_alias = match port {
        Some(port) => format!("acct:{localpart}@{domain}:{port}"),
        None => format!("acct:{localpart}@{domain}"),
    };
    let did_authority = match port {
        Some(port) => format!("{domain}%3A{port}"),
        None => domain.clone(),
    };
    let principal_server_did = format!("did:web:{did_authority}");
    let subject_did = format!("{principal_server_did}:users:{localpart}");

    Some(ParsedUserHandle {
        localpart,
        domain,
        port,
        display,
        handle_uri,
        acct_alias,
        subject_did,
        principal_server_did,
    })
}

fn split_authority(authority: &str) -> Option<(String, Option<u16>)> {
    if authority.is_empty() {
        return None;
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) => {
            let parsed = port.parse::<u16>().ok()?;
            Some((host.to_owned(), Some(parsed)))
        }
        _ => Some((authority.to_owned(), None)),
    }
}

fn valid_localpart(localpart: &str) -> bool {
    !localpart.is_empty()
        && localpart.len() <= 128
        && localpart.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'~' | b'-')
        })
}

fn valid_domain(domain: &str) -> bool {
    let mut labels = domain.split('.');
    let Some(first) = labels.next() else {
        return false;
    };
    if first.is_empty() {
        return false;
    }
    let mut label_count = 1usize;
    if !valid_domain_label(first) {
        return false;
    }
    for label in labels {
        label_count += 1;
        if !valid_domain_label(label) {
            return false;
        }
    }
    label_count >= 2
}

fn valid_domain_label(label: &str) -> bool {
    !label.is_empty()
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_display_handle_to_protocol_parts() {
        let parsed = parse_user_handle("Alice:Example.COM").expect("handle");
        assert_eq!(parsed.display, "alice:example.com");
        assert_eq!(parsed.handle_uri, "contrix://example.com/users/alice");
        assert_eq!(parsed.acct_alias, "acct:alice@example.com");
        assert_eq!(parsed.principal_server_did, "did:web:example.com");
        assert_eq!(parsed.subject_did, "did:web:example.com:users:alice");
    }

    #[test]
    fn accepts_mention_and_acct_alias_inputs() {
        assert_eq!(
            parse_user_handle("@alice:example.com").unwrap().handle_uri,
            "contrix://example.com/users/alice"
        );
        assert_eq!(
            parse_user_handle("alice@example.com").unwrap().handle_uri,
            "contrix://example.com/users/alice"
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
