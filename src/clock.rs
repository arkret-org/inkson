use chrono::{DateTime, Utc};
use garth::HostClock as _;

/// The host wall clock. Both targets go through garth's `HostClock`
/// abstraction: on wasm `chrono`'s `wasmbind` backend reads `Date.now()`, so
/// there is no second client-side clock implementation to keep in step.
pub(crate) fn now_utc() -> DateTime<Utc> {
    garth::SystemClock.now()
}

pub(crate) fn now_unix_ms() -> u64 {
    now_utc().timestamp_millis().max(0) as u64
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

/// Convert an HTML `datetime-local` input value (`YYYY-MM-DDTHH:MM[:SS]`,
/// interpreted in the device-local timezone) into the canonical UTC
/// timestamp the spec schemas require.
pub(crate) fn local_datetime_input_to_canonical(input: &str) -> anyhow::Result<String> {
    let trimmed = input.trim();
    #[cfg(target_arch = "wasm32")]
    {
        let ms = js_sys::Date::parse(trimmed);
        if !ms.is_finite() {
            anyhow::bail!("datetime-local value `{trimmed}` is not parseable");
        }
        let instant = DateTime::<Utc>::from_timestamp_millis(ms as i64)
            .ok_or_else(|| anyhow::anyhow!("datetime-local value `{trimmed}` is out of range"))?;
        Ok(arkret_sdk::canonical::format_timestamp_canonical(instant))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use chrono::TimeZone as _;
        let naive = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S")
            .or_else(|_| chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M"))
            .map_err(|error| anyhow::anyhow!("datetime-local value `{trimmed}`: {error}"))?;
        let local = chrono::Local
            .from_local_datetime(&naive)
            .earliest()
            .ok_or_else(|| {
                anyhow::anyhow!("datetime-local value `{trimmed}` does not exist locally")
            })?;
        Ok(arkret_sdk::canonical::format_timestamp_canonical(
            local.with_timezone(&Utc),
        ))
    }
}

/// Render a canonical UTC timestamp as a `datetime-local` input value in the
/// device-local timezone (edit-form prefill).
pub(crate) fn canonical_to_local_datetime_input(canonical: &str) -> anyhow::Result<String> {
    let instant = DateTime::parse_from_rfc3339(canonical.trim())
        .map_err(|error| anyhow::anyhow!("canonical timestamp `{canonical}`: {error}"))?;
    #[cfg(target_arch = "wasm32")]
    {
        let date = js_sys::Date::new(&instant.to_rfc3339().into());
        let pad = |value: u32| format!("{value:02}");
        Ok(format!(
            "{}-{}-{}T{}:{}",
            date.get_full_year(),
            pad(date.get_month() + 1),
            pad(date.get_date()),
            pad(date.get_hours()),
            pad(date.get_minutes()),
        ))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Ok(instant
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%dT%H:%M")
            .to_string())
    }
}
