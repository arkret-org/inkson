use super::*;

pub(crate) fn merge_personal_handles(
    current: &[String],
    incoming: impl IntoIterator<Item = String>,
) -> Vec<String> {
    let mut seen = BTreeSet::<String>::new();
    let mut merged = Vec::<String>::new();
    let mut push_handle = |handle: String| {
        if let Some(canonical) = canonical_personal_handle(&handle)
            && seen.insert(canonical.clone())
        {
            merged.push(canonical);
        }
    };
    for handle in current {
        push_handle(handle.clone());
    }
    for handle in incoming {
        push_handle(handle);
    }
    merged
}

pub(crate) fn personal_handles_status_for(handles: &[String]) -> String {
    match handles.len() {
        0 => "Not published".to_owned(),
        1 => "1 handle".to_owned(),
        count => format!("{count} handles"),
    }
}

fn canonical_personal_handle(handle: &str) -> Option<String> {
    let trimmed = handle.trim().trim_start_matches('@').trim();
    if trimmed.is_empty() {
        return None;
    }
    crate::identity::handle::normalize_user_handle_display(trimmed)
}

/// Build the account's personal **handle** (`<localpart>:<domain>`) from the
/// `account_me` projection, for the account menu label and the recovery-key
/// download filename.
///
/// `account.handle` (see [`crate::transport::account`]'s `primary_handle_from_viewer`)
/// is the **full canonical handle** carried by the signed primary handle claim
/// — it is *not* a bare localpart. Invalid or empty values are treated as an
/// absent primary handle claim; directory handles and server URLs must not be
/// used as recovery-key filename sources.
pub(crate) fn personal_handle_from_account_handle(account_handle: &str) -> Option<String> {
    let trimmed = account_handle.trim().trim_start_matches('@').trim();
    if trimmed.is_empty() {
        return None;
    }
    crate::identity::handle::normalize_user_handle_display(trimmed)
}

pub(crate) fn server_key(server_url: &str) -> String {
    crate::config::server_url_key(server_url)
}
