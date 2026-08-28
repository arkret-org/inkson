//! Key-backup `supersedes_id` chain construction and verification.

use anyhow::{Result, anyhow};
use serde_json::Value;

use super::selection::backup_series_seq;

/// `sha256:<hex>` over the canonical bytes of the predecessor backup envelope,
/// used to bind a series successor's `supersedes_digest`. Any
/// `auth_data.signature` is stripped first so the digest stays stable across
/// (re)signing. Uploaded envelopes carry `auth_data`, while fresh authoring
/// envelopes do not, so the SDK helper deliberately handles both states.
pub(crate) fn series_supersedes_digest(previous: &Value) -> Result<String> {
    arkret_sdk::KeyBackup::signature_independent_digest_from_wire(previous)
        .map_err(|err| anyhow!("series supersedes digest canonicalization failed: {err}"))
}

/// Generate a fresh protocol `backup_id` for a new envelope in a series.
pub(super) fn fresh_backup_id() -> String {
    format!("ak:backup:{}", crate::operation::uuid_v7())
}

/// Verify the `supersedes_id` chain of a key-backup series back to genesis.
///
/// `tail` is the highest-`series_seq` body selected for the series; `all` is the
/// full set of candidate bodies (same backup class) returned by the server
/// list. The chain is valid only when every `series_seq` from `0..=tail` is
/// present exactly once, each successor's `supersedes_id` points at the immediate
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
        if body.get("supersedes_id").and_then(Value::as_str) != Some(prev_backup_id) {
            return Err(anyhow!(
                "series_chain_broken: series_seq {seq} `supersedes_id` does not point at its predecessor"
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
