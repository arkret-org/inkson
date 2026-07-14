//! Key-backup `supersedes` chain construction and verification.

use anyhow::{Result, anyhow};
use serde_json::Value;

use super::selection::backup_series_seq;

/// Chain a successor backup envelope onto the previous series tail.
///
/// A genesis envelope (no predecessor) keeps its own freshly-generated
/// `series_id` / `series_seq=0` and carries no `supersedes`. A successor
/// inherits the predecessor's `series_id`, bumps `series_seq`, and binds the
/// chain with `supersedes` (the predecessor's `backup_id`) plus
/// `supersedes_digest` (the canonical SHA-256 of the predecessor envelope).
///
/// soland's `enforce_key_backup_series_chain` rejects any `series_seq > 0`
/// envelope that omits `supersedes` / `supersedes_digest` with a
/// `series_chain_broken` 409, so the second and later uploads in a series must
/// carry these fields. The caller MUST give the successor envelope a *fresh*
/// `backup_id` (not the predecessor's) so the predecessor stays persisted as a
/// distinct chain link and `series_predecessor_not_found` is not triggered.
pub(crate) fn apply_next_series(previous: Option<&Value>, body: &mut Value) -> Result<u64> {
    let Some(prev) = previous else {
        return Ok(body.get("series_seq").and_then(Value::as_u64).unwrap_or(0));
    };
    let next_seq = prev.get("series_seq").and_then(Value::as_u64).unwrap_or(0) + 1;
    if let Some(series_id) = prev.get("series_id").and_then(Value::as_str) {
        body["series_id"] = Value::String(series_id.to_owned());
    }
    body["series_seq"] = Value::Number(serde_json::Number::from(next_seq));
    if let Some(prev_backup_id) = prev.get("backup_id").and_then(Value::as_str) {
        body["supersedes"] = Value::String(prev_backup_id.to_owned());
    }
    body["supersedes_digest"] = Value::String(series_supersedes_digest(prev)?);
    Ok(next_seq)
}

/// `sha256:<hex>` over the canonical bytes of the predecessor backup envelope,
/// used to bind a series successor's `supersedes_digest`. Any
/// `auth_data.signature` is stripped first so the digest stays stable across
/// (re)signing (inkson bodies currently carry no `auth_data`, so this is a
/// no-op today, but keeps the digest definition spec-aligned).
pub(super) fn series_supersedes_digest(previous: &Value) -> Result<String> {
    let mut canonical = previous.clone();
    if let Some(auth_data) = canonical
        .get_mut("auth_data")
        .and_then(Value::as_object_mut)
    {
        auth_data.remove("signature");
    }
    crate::canonical::canonical_sha256(&canonical)
        .map_err(|err| anyhow!("series supersedes digest canonicalization failed: {err}"))
}

/// Generate a fresh protocol `backup_id` for a new envelope in a series.
pub(super) fn fresh_backup_id() -> String {
    format!("ak:backup:{}", crate::operation::uuid_v7())
}

/// Verify the `supersedes` chain of a key-backup series back to genesis.
///
/// `tail` is the highest-`series_seq` body selected for the series; `all` is the
/// full set of candidate bodies (same backup class) returned by the server
/// list. The chain is valid only when every `series_seq` from `0..=tail` is
/// present exactly once, each successor's `supersedes` points at the immediate
/// predecessor's `backup_id`, and each `supersedes_digest` matches the canonical
/// digest of that predecessor envelope.
///
/// Returns `Err("series_chain_broken: ...")` on any gap, duplicate, mislinked
/// predecessor, or digest mismatch, so the restore path can fail closed against
/// a server that rolled the series back, forged a high `series_seq`, or withheld
/// an intermediate envelope (per key-management.md series-tail requirements).
pub(super) fn verify_series_chain(tail: &Value, all: &[Value]) -> Result<()> {
    let series_id = tail
        .get("series_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if series_id.is_empty() {
        return Err(anyhow!(
            "series_chain_broken: selected backup has no series_id"
        ));
    }
    let tail_seq = backup_series_seq(tail);
    let mut by_seq: std::collections::BTreeMap<u64, &Value> = std::collections::BTreeMap::new();
    for body in all {
        if body.get("series_id").and_then(Value::as_str) != Some(series_id) {
            continue;
        }
        let seq = backup_series_seq(body);
        if by_seq.insert(seq, body).is_some() {
            return Err(anyhow!(
                "series_chain_broken: duplicate series_seq {seq} in series {series_id}"
            ));
        }
    }
    for seq in 0..=tail_seq {
        let Some(body) = by_seq.get(&seq) else {
            return Err(anyhow!(
                "series_chain_broken: missing series_seq {seq} in series {series_id}"
            ));
        };
        if seq == 0 {
            continue;
        }
        let Some(prev) = by_seq.get(&(seq - 1)) else {
            return Err(anyhow!(
                "series_chain_broken: missing predecessor series_seq {} in series {series_id}",
                seq - 1
            ));
        };
        let prev_backup_id = prev
            .get("backup_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if body.get("supersedes").and_then(Value::as_str) != Some(prev_backup_id) {
            return Err(anyhow!(
                "series_chain_broken: series_seq {seq} `supersedes` does not point at its predecessor"
            ));
        }
        let expected_digest = series_supersedes_digest(prev)?;
        if body.get("supersedes_digest").and_then(Value::as_str) != Some(expected_digest.as_str()) {
            return Err(anyhow!(
                "series_chain_broken: series_seq {seq} `supersedes_digest` mismatch"
            ));
        }
    }
    Ok(())
}
