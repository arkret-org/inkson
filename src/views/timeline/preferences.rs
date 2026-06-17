use crate::local_state::LocalStateStore;

pub(super) const ATTACHMENT_BYTES: &[u8] = b"yougen encrypted bytes";

pub(crate) const TIMELINE_ENCRYPT_LOCAL_DEFAULT_KEY: &str = "timeline.encrypt_local_default";
pub(crate) const TIMELINE_INCIDENT_PRIORITY_KEY: &str = "timeline.incident_priority";
pub(crate) const TIMELINE_PUBLIC_UPDATE_GUARD_KEY: &str = "timeline.public_update_guard";
pub(crate) const TIMELINE_PRIVATE_PLAINTEXT_KEY: &str = "timeline.private_plaintext";
pub(crate) const TIMELINE_PLAINTEXT_ACK_KEY: &str = "timeline.plaintext_ack";

pub(super) const EMOJI_GRID: &[&str] = &[
    "\u{1f44d}",
    "\u{2764}\u{fe0f}",
    "\u{1f602}",
    "\u{1f62e}",
    "\u{1f622}",
    "\u{1f389}",
    "\u{1f525}",
    "\u{1f44e}",
    "\u{1f64f}",
    "\u{1f440}",
    "\u{1f4af}",
    "\u{1f680}",
];

pub(crate) fn timeline_private_data_bool(
    store: &LocalStateStore,
    account_key: &str,
    key: &str,
    default_value: bool,
) -> bool {
    store
        .load_private_data(account_key, key)
        .as_deref()
        .map(|value| matches!(value, "true" | "1" | "yes" | "on"))
        .unwrap_or(default_value)
}

pub(crate) fn timeline_incident_priority_preference(
    store: &LocalStateStore,
    account_key: &str,
) -> String {
    match store.load_private_data(account_key, TIMELINE_INCIDENT_PRIORITY_KEY) {
        Some(value) if matches!(value.as_str(), "sev1" | "sev2" | "sev3" | "normal") => value,
        _ => "normal".to_owned(),
    }
}

pub(crate) fn plaintext_visible_service(base_url: &str) -> String {
    base_url
        .split_once("://")
        .and_then(|(_, rest)| rest.split('/').next())
        .filter(|host| !host.is_empty())
        .map(|host| format!("configured server {host}"))
        .unwrap_or_else(|| "configured server".to_owned())
}
