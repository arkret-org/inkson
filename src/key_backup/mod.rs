use serde_json::Value;

mod build;
#[cfg(test)]
mod domain_sep;
mod signing;

pub use build::*;
#[cfg(test)]
pub use domain_sep::*;
pub use signing::*;

#[cfg(test)]
mod tests;

pub use arkret_sdk::BackupKind;

pub(crate) fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} is required"))
}

pub(crate) fn required_str_anyhow<'a>(value: &'a Value, key: &str) -> anyhow::Result<&'a str> {
    required_str(value, key).map_err(|err| anyhow::anyhow!(err))
}
