use chrono::{DateTime, Utc};

#[cfg(target_arch = "wasm32")]
pub(crate) fn now_unix_ms() -> u64 {
    js_sys::Date::now().max(0.0).floor() as u64
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn now_unix_ms() -> u64 {
    Utc::now().timestamp_millis().max(0) as u64
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn now_utc() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp_millis(now_unix_ms() as i64)
        .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn now_utc() -> DateTime<Utc> {
    Utc::now()
}

pub(crate) fn now_utc_canonical() -> DateTime<Utc> {
    arkret_sdk::canonical::normalize_timestamp_canonical(now_utc())
}

pub(crate) fn now_timestamp() -> String {
    arkret_sdk::canonical::format_timestamp_canonical(now_utc())
}

/// Canonical Event/proof timestamp with exactly three UTC millisecond digits.
pub(crate) fn now_utc_millis() -> DateTime<Utc> {
    arkret_sdk::canonical::normalize_timestamp_canonical(now_utc())
}

/// Canonical Arkret timestamp `minutes` into the future. Used to
/// stamp `DeviceMessageEnvelope.expires_at`, which `device-lifecycle.md` §7
/// makes a required to-device queue field (default cap 24h; verification and
/// secret-share strands use much shorter windows).
pub(crate) fn timestamp_in(minutes: i64) -> String {
    arkret_sdk::canonical::format_timestamp_canonical(
        now_utc() + chrono::Duration::minutes(minutes),
    )
}
