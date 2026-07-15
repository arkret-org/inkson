//! Friendly device-name display helpers.
//!
//! Produces a short `device_id` fragment used to tell same-named devices
//! apart in the UI.
//!
//! Spec: `crypto-media/device-lifecycle.md` §4 — `display_name` is the
//! optional, user-facing, mutable device name; the canonical identifier
//! is always `device_id` (`ak:device:<uuidv7>`).

/// Return a short, stable fragment of a `device_id` for disambiguating
/// devices that share a `display_name`. Uses the tail of the UUID
/// (its random low bits for UUIDv7), keeping the last 6 hex digits.
pub fn device_id_short_suffix(device_id: &str) -> String {
    let tail = device_id.rsplit(':').next().unwrap_or(device_id);
    let cleaned: String = tail
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase();
    let len = cleaned.len();
    if len == 0 {
        return String::new();
    }
    cleaned[len.saturating_sub(6)..].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_suffix_takes_last_six_hex() {
        assert_eq!(
            device_id_short_suffix("ak:device:019640dd-8000-7000-8000-0000000abc12"),
            "0abc12"
        );
    }

    #[test]
    fn short_suffix_handles_plain_and_empty() {
        assert_eq!(device_id_short_suffix("abcdef123456"), "123456");
        assert_eq!(device_id_short_suffix(""), "");
        assert_eq!(device_id_short_suffix("ak:device:"), "");
    }
}
