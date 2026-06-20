//! Ephemeral / durable envelope builders and submit-acceptance helpers for the
//! self-API client: outgoing-payload schema validation, read-cursor advance
//! events, the `ck.typing` / `ck.receipt.read` / `ck.presence` /
//! `ck.call.signal` ephemeral envelopes, and the events-batch acceptance gate.
//! Structural move out of `api/mod.rs` with no logic change; the helpers used
//! by the `events` sibling module and tests stay `pub(crate)` and the free
//! builders are re-exported from the parent module so existing `crate::api::*`
//! / sibling `super::*` paths resolve unchanged.

use super::*;

pub(crate) fn validate_outgoing_registered_event_payload(
    kind: &str,
    payload: &Value,
) -> anyhow::Result<()> {
    let catalog = cokret_sdk::schema::event_payload_validator_catalog();
    if !catalog
        .missing_payload_validators_for(std::iter::once(kind))
        .is_empty()
    {
        return Ok(());
    }

    catalog.validate_payload(kind, payload).map_err(|err| {
        anyhow::anyhow!(
            "outgoing event kind '{kind}' payload violates registered payload schema: {err}"
        )
    })
}

pub fn build_read_cursor_advance_event(
    marker: &crate::local_state::ReadMarkerRecord,
) -> EventEnvelope {
    OperationBuilder::new(&marker.body.realm_id, &marker.actor, &marker.marker_type)
        .body(marker.ck_read_cursor_payload())
        .build(&marker.device_id)
}

pub(crate) fn ensure_events_submit_batch_accepted(response: &Value) -> anyhow::Result<()> {
    let status = response
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("accepted");
    let rejected = response
        .get("rejected")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if rejected.is_empty() && matches!(status, "accepted" | "duplicate") {
        return Ok(());
    }

    let details = rejected
        .iter()
        .map(|item| {
            let id = item.get("id").and_then(Value::as_str).unwrap_or("unknown");
            let reason = item
                .get("reason_code")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let detail = item.get("detail").and_then(Value::as_str).unwrap_or("");
            if detail.is_empty() {
                format!("{id}:{reason}")
            } else {
                format!("{id}:{reason}:{detail}")
            }
        })
        .collect::<Vec<_>>()
        .join("; ");
    anyhow::bail!(
        "events batch submit was not fully accepted: status={status}, rejected=[{details}]"
    );
}

/// Round R2/R3 (T02) — default ephemeral TTL for long-lived ephemeral
/// fanout such as `ck.presence` / `ck.receipt.read`. 30 seconds is
/// comfortably below the 5-minute hard ceiling.
const EPHEMERAL_DEFAULT_TTL_SECS: i64 = 30;
const TYPING_EPHEMERAL_TTL_SECS: i64 = 5;

/// Round R2/R3 (T02) — build a `ck.typing` `EphemeralEnvelope`. Enforces
/// the kind allowlist + the 5-minute hard ceiling on `expires_at - sent_at`.
pub fn build_typing_envelope(
    realm_id: &str,
    actor_id: &str,
    device_id: Option<&str>,
    typing: bool,
) -> anyhow::Result<cokret_sdk::EphemeralEnvelope> {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(TYPING_EPHEMERAL_TTL_SECS);
    let realm_id_wire = trim_realm_id(realm_id);
    let realm = cokret_sdk::RealmId::new(realm_id_wire.clone())
        .map_err(|err| anyhow::anyhow!("invalid realm_id for ck.typing: {err}"))?;
    let actor = cokret_sdk::Did::new(actor_id)
        .map_err(|err| anyhow::anyhow!("invalid actor_id for ck.typing: {err}"))?;
    let device = device_id
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            cokret_sdk::DeviceId::new(s)
                .map_err(|err| anyhow::anyhow!("invalid device_id for ck.typing: {err}"))
        })
        .transpose()?;
    cokret_sdk::EphemeralEnvelope::new(
        "ck.typing",
        realm,
        actor,
        device,
        now,
        expires_at,
        json!({
            "actor_id": actor_id,
            "realm_id": realm_id_wire,
            "scope_id": realm_id,
            "typing": typing,
            "ttl_ms": TYPING_EPHEMERAL_TTL_SECS * 1000
        }),
        None,
    )
    .map_err(|err| anyhow::anyhow!("typing envelope rejected: {err}"))
}

/// Round R2/R3 (T02) — build a `ck.receipt.read` `EphemeralEnvelope`.
pub fn build_receipt_read_envelope(
    realm_id: &str,
    actor_id: &str,
    event_id: &str,
) -> anyhow::Result<cokret_sdk::EphemeralEnvelope> {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(EPHEMERAL_DEFAULT_TTL_SECS);
    let realm_id_wire = trim_realm_id(realm_id);
    let realm = cokret_sdk::RealmId::new(realm_id_wire.clone())
        .map_err(|err| anyhow::anyhow!("invalid realm_id for ck.receipt.read: {err}"))?;
    let actor = cokret_sdk::Did::new(actor_id)
        .map_err(|err| anyhow::anyhow!("invalid actor_id for ck.receipt.read: {err}"))?;
    cokret_sdk::EphemeralEnvelope::new(
        "ck.receipt.read",
        realm,
        actor,
        None,
        now,
        expires_at,
        json!({
            "receipt_type": "read",
            "schema": "ck.schema.read_receipt.v1",
            "realm_id": realm_id_wire,
            "actor_id": actor_id,
            "event_id": event_id,
            "created_at": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        }),
        None,
    )
    .map_err(|err| anyhow::anyhow!("read receipt envelope rejected: {err}"))
}

/// Round R2/R3 (T02) — build a `ck.presence` `EphemeralEnvelope`.
pub fn build_presence_envelope(
    realm_id: &str,
    actor_id: &str,
    status: &str,
    last_active_at: Option<chrono::DateTime<chrono::Utc>>,
) -> anyhow::Result<cokret_sdk::EphemeralEnvelope> {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(EPHEMERAL_DEFAULT_TTL_SECS);
    let realm = cokret_sdk::RealmId::new(realm_id)
        .map_err(|err| anyhow::anyhow!("invalid realm_id for ck.presence: {err}"))?;
    let actor = cokret_sdk::Did::new(actor_id)
        .map_err(|err| anyhow::anyhow!("invalid actor_id for ck.presence: {err}"))?;
    let mut payload = serde_json::Map::new();
    payload.insert("actor_id".into(), Value::String(actor_id.to_owned()));
    payload.insert("status".into(), Value::String(status.to_owned()));
    if let Some(ts) = last_active_at {
        payload.insert("last_active_at".into(), Value::String(ts.to_rfc3339()));
    }
    cokret_sdk::EphemeralEnvelope::new(
        "ck.presence",
        realm,
        actor,
        None,
        now,
        expires_at,
        Value::Object(payload),
        None,
    )
    .map_err(|err| anyhow::anyhow!("presence envelope rejected: {err}"))
}

/// Round 4 (spec a77b995) — build a `ck.call.signal` `EphemeralEnvelope`.
///
/// Wire-breaking vs. the round R2/R3 form: the payload shape moved from
/// `{call_id, kind, payload}` to the canonical
/// [`cokret_sdk::CallSignalPayload`] `{call_id, signal_type, seq, data}`
/// where `signal_type` MUST be one of [`cokret_sdk::CALL_SIGNAL_TYPES`]
/// (13 values: `invite`, `answer`, `candidate`, `renegotiate`, `hangup`,
/// `ack`, `reject`, `mute_state`, `media_state`, `speaking`, `focus_join`,
/// `focus_leave`, `error`). `device_id` + `proof` are REQUIRED on the
/// envelope; `seq` is strictly monotonic per
/// `(realm_id, call_id, actor, device)` (callers manage the counter via
/// [`cokret_sdk::CallSignalState`]).
///
/// The caller MUST attach a device-signed proof via the active
/// [`crate::event_signer`] before submit — the bare envelope returned
/// here carries `proof = None` and the submit guard / receiver will
/// reject it. See [`super::CokretApi::submit_call_signal_v1`] for the
/// signing + submit path.
pub fn build_call_signal_envelope_v1(
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    call_id: &str,
    signal_type: &str,
    seq: u64,
    data: Value,
) -> anyhow::Result<cokret_sdk::EphemeralEnvelope> {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(EPHEMERAL_DEFAULT_TTL_SECS);
    let realm = cokret_sdk::RealmId::new(realm_id)
        .map_err(|err| anyhow::anyhow!("invalid realm_id for ck.call.signal: {err}"))?;
    let actor = cokret_sdk::Did::new(actor_id)
        .map_err(|err| anyhow::anyhow!("invalid actor_id for ck.call.signal: {err}"))?;
    if device_id.trim().is_empty() {
        anyhow::bail!("ck.call.signal requires non-empty device_id (round 4 schema_violation)");
    }
    let device = Some(
        cokret_sdk::DeviceId::new(device_id)
            .map_err(|err| anyhow::anyhow!("invalid device_id for ck.call.signal: {err}"))?,
    );
    if !cokret_sdk::CALL_SIGNAL_TYPES.contains(&signal_type) {
        anyhow::bail!("ck.call.signal signal_type {signal_type:?} not in canonical 13-value enum");
    }
    let call = cokret_sdk::CallId::new(call_id)
        .map_err(|err| anyhow::anyhow!("invalid call_id for ck.call.signal: {err}"))?;
    let payload = cokret_sdk::CallSignalPayload {
        call_id: call,
        signal_type: signal_type.to_owned(),
        seq,
        data,
    };
    payload
        .validate_signal_type()
        .map_err(|err| anyhow::anyhow!("ck.call.signal payload rejected: {err}"))?;
    cokret_sdk::EphemeralEnvelope::new(
        "ck.call.signal",
        realm,
        actor,
        device,
        now,
        expires_at,
        serde_json::to_value(payload)?,
        None,
    )
    .map_err(|err| anyhow::anyhow!("call signal envelope rejected: {err}"))
}
