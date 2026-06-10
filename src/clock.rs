use chrono::{DateTime, SecondsFormat, Utc};

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

pub(crate) fn now_rfc3339_secs() -> String {
    now_utc().to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// RFC3339 (seconds precision) timestamp `minutes` into the future. Used to
/// stamp `DeviceMessageEnvelope.expires_at`, which `device-lifecycle.md` §7
/// makes a required to-device queue field (default cap 24h; verification and
/// secret-share flows use much shorter windows).
pub(crate) fn rfc3339_secs_in(minutes: i64) -> String {
    (now_utc() + chrono::Duration::minutes(minutes)).to_rfc3339_opts(SecondsFormat::Secs, true)
}
