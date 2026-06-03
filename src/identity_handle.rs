/// Utilities for Cokret user handles.
///
/// R3.1 wire form (cokret-spec @ 7157ee8): the canonical handle is
/// `<localpart>:<domain>(:<port>)?`. The previous `cokret://domain/users/local`
/// URI form has been retired. `acct:<localpart>@<domain>` remains an interop
/// alias only.
///
/// Realm membership materialises the resolved user DID plus the recipient
/// Principal Server DID, never the display string itself.
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

    // R3.1: the cokret:// URI handle form is retired. Inputs are
    // `<localpart>:<domain>` or `acct:<localpart>@<domain>`.
    if trimmed.starts_with("cokret://") {
        return None;
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

    let canonical = match port {
        Some(port) => format!("{localpart}:{domain}:{port}"),
        None => format!("{localpart}:{domain}"),
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
        display: canonical.clone(),
        handle: canonical,
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

/// R3 spec sync (b47ff6ec) — wire-level handle homograph guard.
///
/// `zh/identity/identity-handles.md §17` requires that the canonical
/// compare on handles performs Unicode NFC + UTS#39 confusable skeleton
/// folding, and that script-mixed handles (Latin + Cyrillic / Greek /
/// Armenian) are rejected at the wire level with
/// `failed_precondition reason="handle_homograph_forbidden"`.
///
/// This client-side helper performs the same script-mix detection so
/// the registration form can surface an inline warning before the
/// server returns the error. The check is intentionally conservative:
/// it groups characters into a small set of script families and flags
/// any handle that crosses the visually-confusable boundary
/// (Latin↔Cyrillic / Latin↔Greek / Latin↔Armenian / Cyrillic↔Greek).
///
/// Returns `Some(reason)` when the handle should be rejected;
/// `None` otherwise.
///
/// TODO(R3.1): replace the ad-hoc script classifier below with a real
/// UTS#39 skeleton-fold implementation once the SDK ships
/// `contrix_sdk::identity::handle_canonical_form`. Until then this
/// client-side check is best-effort — the server is the source of
/// truth and will return `handle_homograph_forbidden` if the form is
/// rejected.
pub fn detect_handle_homograph_risk(localpart: &str) -> Option<HandleHomographRisk> {
    let mut scripts = std::collections::BTreeSet::new();
    for ch in localpart.chars() {
        if let Some(script) = classify_script(ch) {
            scripts.insert(script);
        }
    }
    // ASCII / digits / punctuation are not script-bearing.
    scripts.remove(&HandleScript::Neutral);
    // Single script (or none) is fine.
    if scripts.len() <= 1 {
        return None;
    }
    // Any script mix surfaces a warning. The most common confusable
    // pairs (Latin + Cyrillic / Greek / Armenian) match the spec's
    // explicit reject set; we surface a generic warning for all mixes.
    let scripts_vec: Vec<HandleScript> = scripts.into_iter().collect();
    Some(HandleHomographRisk {
        scripts: scripts_vec,
    })
}

/// Script-family classification used by [`detect_handle_homograph_risk`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HandleScript {
    /// ASCII + digits + handle-safe punctuation; not script-bearing.
    Neutral,
    Latin,
    Cyrillic,
    Greek,
    Armenian,
    Cjk,
    Other,
}

impl HandleScript {
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Neutral => "neutral",
            Self::Latin => "Latin",
            Self::Cyrillic => "Cyrillic",
            Self::Greek => "Greek",
            Self::Armenian => "Armenian",
            Self::Cjk => "CJK",
            Self::Other => "other",
        }
    }
}

/// Carries the list of script families detected in a script-mixed handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandleHomographRisk {
    pub scripts: Vec<HandleScript>,
}

impl HandleHomographRisk {
    /// Human-readable script list for an inline warning, e.g.
    /// `"Latin + Cyrillic"`.
    pub fn script_label(&self) -> String {
        self.scripts
            .iter()
            .map(|s| s.as_label())
            .collect::<Vec<_>>()
            .join(" + ")
    }
}

fn classify_script(ch: char) -> Option<HandleScript> {
    // ASCII letters carry an inherent Latin script identity, so an
    // ASCII-letter handle mixed with Cyrillic / Greek look-alikes is
    // detected as Latin + (other). ASCII digits and handle-safe
    // punctuation are script-neutral and don't flip the mix detector.
    if ch.is_ascii_alphabetic() {
        return Some(HandleScript::Latin);
    }
    if ch.is_ascii_digit() || matches!(ch, '.' | '_' | '+' | '~' | '-') {
        return Some(HandleScript::Neutral);
    }
    let code = ch as u32;
    // U+0400-U+04FF Cyrillic; U+0500-U+052F Cyrillic Supplement
    if (0x0400..=0x052F).contains(&code) {
        return Some(HandleScript::Cyrillic);
    }
    // U+0370-U+03FF Greek
    if (0x0370..=0x03FF).contains(&code) {
        return Some(HandleScript::Greek);
    }
    // U+0530-U+058F Armenian
    if (0x0530..=0x058F).contains(&code) {
        return Some(HandleScript::Armenian);
    }
    // CJK Unified Ideographs / Hiragana / Katakana / Hangul (rough range).
    if (0x3040..=0x30FF).contains(&code)
        || (0x3400..=0x9FFF).contains(&code)
        || (0xAC00..=0xD7AF).contains(&code)
    {
        return Some(HandleScript::Cjk);
    }
    if ch.is_alphabetic() {
        // Non-ASCII Latin (e.g. accented letters) — treat as Latin so
        // accented + ASCII is not falsely flagged as a mix.
        let upper = ch.to_uppercase().next().unwrap_or(ch);
        if (upper as u32) < 0x0250 {
            return Some(HandleScript::Latin);
        }
        return Some(HandleScript::Other);
    }
    None
}

/// R3 — returns `true` when the input contains any non-NFC characters
/// that would be normalised on the wire. The detection is conservative:
/// it currently flags any combining mark in the input (the most common
/// NFC-NFD divergence). A `true` result means the handle will be
/// canonicalised by the server; the client should surface an inline
/// warning explaining that the displayed form may change.
///
/// TODO(R3.1): swap this for the SDK's real `nfc_normalise` once that
/// lands so the warning fires on the full NFC class, not just combining
/// marks.
pub fn handle_will_be_nfc_normalised(localpart: &str) -> bool {
    localpart.chars().any(|ch| {
        let code = ch as u32;
        // U+0300..U+036F: Combining Diacritical Marks
        (0x0300..=0x036F).contains(&code)
    })
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
        // 'е' is U+0435 Cyrillic small letter ie (visually identical to
        // Latin 'e'); mixed with ASCII 'alic' = Latin.
        let risk = detect_handle_homograph_risk("alicе").expect("flagged");
        assert!(risk.scripts.contains(&HandleScript::Latin));
        assert!(risk.scripts.contains(&HandleScript::Cyrillic));
    }

    #[test]
    fn latin_plus_greek_is_flagged() {
        // 'α' is U+03B1 Greek small letter alpha.
        let risk = detect_handle_homograph_risk("aliceα").expect("flagged");
        assert!(risk.scripts.contains(&HandleScript::Greek));
    }

    #[test]
    fn pure_cyrillic_is_not_flagged() {
        assert!(detect_handle_homograph_risk("алиса").is_none());
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
