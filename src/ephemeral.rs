//! Ephemeral / durable envelope builders and submit-acceptance helpers for the
//! self client: outgoing-payload schema validation, read-cursor advance events,
//! the `ck.typing` / `ck.receipt.read` / `ck.presence` / `ck.call.signal`
//! ephemeral envelopes, and the events-batch acceptance gate.

use chrono::Timelike as _;
use serde_json::{Value, json};

use crate::operation::{EventKind, OperationBuilder, trim_realm_id};

pub(crate) fn validate_outgoing_registered_event_payload(
    kind: &str,
    payload: &Value,
) -> anyhow::Result<()> {
    let catalog = arkret_sdk::schema::event_payload_validator_catalog()?;
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
) -> anyhow::Result<arkret_sdk::Event> {
    let kind = EventKind::try_new(&marker.marker_type).ok_or_else(|| {
        anyhow::anyhow!(
            "read marker kind {:?} is not in the SDK event-kind registry",
            marker.marker_type
        )
    })?;
    OperationBuilder::new(&marker.body.realm_id, &marker.actor, kind)
        .body(marker.ck_read_cursor_payload())
        .build_sdk_event(&marker.device_id)
}

pub(crate) fn ensure_events_submit_accepted(
    response: &arkret_sdk::EventsSubmitOutcome,
) -> anyhow::Result<()> {
    if response.rejected.is_empty()
        && matches!(
            response.status,
            arkret_sdk::EventsSubmitStatus::Accepted | arkret_sdk::EventsSubmitStatus::Duplicate
        )
    {
        return Ok(());
    }

    let details = response
        .rejected
        .iter()
        .map(|item| {
            let id = item.id.as_str();
            let reason = item.reason_code.as_str();
            let detail = item.detail.as_deref().unwrap_or("");
            if detail.is_empty() {
                format!("{id}:{reason}")
            } else {
                format!("{id}:{reason}:{detail}")
            }
        })
        .collect::<Vec<_>>()
        .join("; ");
    let status = match response.status {
        arkret_sdk::EventsSubmitStatus::Accepted => "accepted",
        arkret_sdk::EventsSubmitStatus::Duplicate => "duplicate",
        arkret_sdk::EventsSubmitStatus::Partial => "partial",
        arkret_sdk::EventsSubmitStatus::HistoricalOnly => "historical_only",
    };
    anyhow::bail!("events submit was not fully accepted: status={status}, rejected=[{details}]");
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
    device_id: &str,
    strand_id: &str,
    typing: bool,
) -> anyhow::Result<arkret_sdk::EphemeralEnvelope> {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(TYPING_EPHEMERAL_TTL_SECS);
    let realm_id_wire = trim_realm_id(realm_id);
    let realm = arkret_sdk::RealmId::new(realm_id_wire.clone())
        .map_err(|err| anyhow::anyhow!("invalid realm_id for ck.typing: {err}"))?;
    let actor = arkret_sdk::Did::new(actor_id)
        .map_err(|err| anyhow::anyhow!("invalid actor_id for ck.typing: {err}"))?;
    let strand = arkret_sdk::StrandId::new(strand_id.trim().to_owned())
        .map_err(|err| anyhow::anyhow!("invalid strand_id for ck.typing: {err}"))?;
    // ephemeral-envelope.schema.json: device_id is REQUIRED for every
    // broadcast ephemeral kind; the proof binds to `{actor_id}#{device_id}`.
    let device = Some(
        arkret_sdk::DeviceId::new(device_id)
            .map_err(|err| anyhow::anyhow!("invalid device_id for ck.typing: {err}"))?,
    );
    arkret_sdk::EphemeralEnvelope::new(
        "ak.typing",
        realm,
        actor,
        device,
        now,
        expires_at,
        json!({
            "actor_id": actor_id,
            "realm_id": realm_id_wire,
            "strand_id": strand.as_str(),
            // ephemeral-envelope.schema.json ck.typing branch: optional, const
            // "discussion" in v1 — the only writable Message timeline.
            "track_name": "discussion",
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
    device_id: &str,
    strand_id: &str,
    event_id: &str,
) -> anyhow::Result<arkret_sdk::EphemeralEnvelope> {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(EPHEMERAL_DEFAULT_TTL_SECS);
    let realm_id_wire = trim_realm_id(realm_id);
    let realm = arkret_sdk::RealmId::new(realm_id_wire.clone())
        .map_err(|err| anyhow::anyhow!("invalid realm_id for ak.receipt.read: {err}"))?;
    let actor = arkret_sdk::Did::new(actor_id)
        .map_err(|err| anyhow::anyhow!("invalid actor_id for ak.receipt.read: {err}"))?;
    let strand = arkret_sdk::StrandId::new(strand_id.trim().to_owned())
        .map_err(|err| anyhow::anyhow!("invalid strand_id for ak.receipt.read: {err}"))?;
    let event = arkret_sdk::EventId::new(event_id.trim().to_owned())
        .map_err(|err| anyhow::anyhow!("invalid event_id for ak.receipt.read: {err}"))?;
    let receipt = arkret_sdk::ReadReceipt {
        receipt_type: "read".to_owned(),
        schema: arkret_sdk::READ_RECEIPT_SCHEMA.to_owned(),
        realm_id: realm.clone(),
        actor_id: actor.clone(),
        event_id: event,
        hlc: None,
        read_scope: arkret_sdk::ReadScope::strand(strand.as_str().to_owned(), Some("discussion")),
        created_at: now,
    };
    let device = arkret_sdk::DeviceId::new(device_id)
        .map_err(|err| anyhow::anyhow!("invalid device_id for ak.receipt.read: {err}"))?;
    arkret_sdk::EphemeralEnvelope::new(
        "ak.receipt.read",
        realm,
        actor,
        Some(device),
        now,
        expires_at,
        serde_json::to_value(receipt)?,
        None,
    )
    .map_err(|err| anyhow::anyhow!("read receipt envelope rejected: {err}"))
}

/// Round R2/R3 (T02) — build a `ck.presence` `EphemeralEnvelope`.
pub fn build_presence_envelope(
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    state: &str,
    status_message: Option<&str>,
    last_active_at: Option<chrono::DateTime<chrono::Utc>>,
) -> anyhow::Result<arkret_sdk::EphemeralEnvelope> {
    if arkret_sdk::PresenceStatus::parse_wire(state).is_none() {
        anyhow::bail!("ak.presence state {state:?} is not a canonical presence state");
    }
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(EPHEMERAL_DEFAULT_TTL_SECS);
    let realm_id_wire = trim_realm_id(realm_id);
    let realm = arkret_sdk::RealmId::new(realm_id_wire.clone())
        .map_err(|err| anyhow::anyhow!("invalid realm_id for ck.presence: {err}"))?;
    let actor = arkret_sdk::Did::new(actor_id)
        .map_err(|err| anyhow::anyhow!("invalid actor_id for ck.presence: {err}"))?;
    let mut payload = serde_json::Map::new();
    payload.insert("realm_id".into(), Value::String(realm_id_wire));
    payload.insert("actor_id".into(), Value::String(actor_id.to_owned()));
    payload.insert("state".into(), Value::String(state.to_owned()));
    if let Some(message) = status_message.map(str::trim).filter(|m| !m.is_empty()) {
        // Sender-side fail-closed: the same constraint the server
        // enforces at admission (≤256 code points, NFC, no control
        // chars). NFC-normalize proactively for free-typed text.
        let message = arkret_sdk::canonical::to_nfc(message);
        arkret_sdk::validate_status_message(&message)
            .map_err(|err| anyhow::anyhow!("ak.presence status_message rejected: {err}"))?;
        payload.insert("status_message".into(), Value::String(message));
    }
    if let Some(ts) = last_active_at {
        payload.insert(
            "last_active_at".into(),
            Value::String(bucket_presence_timestamp(ts)),
        );
    }
    payload.insert(
        "ttl_ms".into(),
        Value::Number((EPHEMERAL_DEFAULT_TTL_SECS * 1000).into()),
    );
    let device = arkret_sdk::DeviceId::new(device_id)
        .map_err(|err| anyhow::anyhow!("invalid device_id for ck.presence: {err}"))?;
    arkret_sdk::EphemeralEnvelope::new(
        "ak.presence",
        realm,
        actor,
        Some(device),
        now,
        expires_at,
        Value::Object(payload),
        None,
    )
    .map_err(|err| anyhow::anyhow!("presence envelope rejected: {err}"))
}

fn bucket_presence_timestamp(ts: chrono::DateTime<chrono::Utc>) -> String {
    let bucketed = ts.timestamp() - ts.timestamp().rem_euclid(60 * 60);
    let start = chrono::DateTime::<chrono::Utc>::from_timestamp(bucketed, 0)
        .unwrap_or(ts)
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    format!("{start}/PT1H")
}

/// Round 4 (spec a77b995) — build a `ck.call.signal` `EphemeralEnvelope`.
///
/// Wire-breaking vs. the round R2/R3 form: the payload shape moved from
/// `{call_id, kind, payload}` to the canonical
/// [`arkret_sdk::CallSignalPayload`] `{call_id, signal_type, seq, data}`
/// where `signal_type` MUST be one of [`arkret_sdk::CALL_SIGNAL_TYPES`]
/// (13 values: `invite`, `answer`, `candidate`, `renegotiate`, `hangup`,
/// `ack`, `reject`, `mute_state`, `media_state`, `speaking`, `focus_join`,
/// `focus_leave`, `error`). `device_id` + `proof` are REQUIRED on the
/// envelope; `seq` is strictly monotonic per
/// `(realm_id, call_id, actor, device)` (callers manage the counter via
/// [`arkret_sdk::CallSignalState`]).
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
) -> anyhow::Result<arkret_sdk::EphemeralEnvelope> {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(EPHEMERAL_DEFAULT_TTL_SECS);
    let realm = arkret_sdk::RealmId::new(realm_id)
        .map_err(|err| anyhow::anyhow!("invalid realm_id for ak.call.signal: {err}"))?;
    let actor = arkret_sdk::Did::new(actor_id)
        .map_err(|err| anyhow::anyhow!("invalid actor_id for ak.call.signal: {err}"))?;
    if device_id.trim().is_empty() {
        anyhow::bail!("ak.call.signal requires non-empty device_id (round 4 schema_violation)");
    }
    let device = Some(
        arkret_sdk::DeviceId::new(device_id)
            .map_err(|err| anyhow::anyhow!("invalid device_id for ak.call.signal: {err}"))?,
    );
    if !arkret_sdk::CALL_SIGNAL_TYPES.contains(&signal_type) {
        anyhow::bail!("ak.call.signal signal_type {signal_type:?} not in canonical 13-value enum");
    }
    let call = arkret_sdk::CallId::new(call_id)
        .map_err(|err| anyhow::anyhow!("invalid call_id for ak.call.signal: {err}"))?;
    let payload = arkret_sdk::CallSignalPayload {
        call_id: call,
        signal_type: signal_type.to_owned(),
        seq,
        data,
    };
    payload
        .validate_signal_type()
        .map_err(|err| anyhow::anyhow!("ak.call.signal payload rejected: {err}"))?;
    arkret_sdk::EphemeralEnvelope::new(
        "ak.call.signal",
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

/// Attach the broadcast ephemeral `proof` required by
/// `ephemeral-envelope.schema.json` for all four broadcast kinds: a detached
/// JWS from the active device signer whose `verification_method` is
/// `{actor_id}#{device_id}` (fragment = the full `ak:device:<uuidv7>` id) and
/// whose `event_digest` covers the canonical envelope bytes without `proof`.
/// Fails closed when no signer is installed — an unsigned broadcast ephemeral
/// never goes on the wire.
pub(crate) fn attach_broadcast_ephemeral_proof(
    envelope: &mut arkret_sdk::EphemeralEnvelope,
) -> anyhow::Result<()> {
    let kind = envelope.kind.clone();
    let device_id = envelope
        .device_id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("{kind} proof requires envelope.device_id"))?
        .as_str()
        .to_owned();
    let signer = crate::event_signer::active_signer().ok_or_else(|| {
        anyhow::anyhow!("no active signer configured — cannot submit {kind} without device proof")
    })?;

    // event_digest covers the canonical envelope bytes without `proof`.
    envelope.proof = None;
    let canonical_bytes = arkret_sdk::signatures::proof::EventProofBuilder::new()
        .canonical_bytes(&serde_json::to_value(&*envelope)?)
        .map_err(|err| anyhow::anyhow!("{kind} canonical encoding failed: {err}"))?;
    let event_digest = arkret_sdk::Hash::new(crate::canonical::sha256_digest(&canonical_bytes))
        .map_err(|err| anyhow::anyhow!("{kind} event digest is not a typed Hash: {err}"))?;

    // Typed `Proof` + the SDK's canonical binding-object constructor — the
    // same transcript the receiver-side verifier rebuilds, so producer and
    // verifier can never drift.
    let mut proof = arkret_sdk::Proof {
        kind: arkret_sdk::proof_kind::DETACHED_JWS.to_owned(),
        alg: signer.algorithm().to_owned(),
        verification_method: format!("{}#{device_id}", envelope.actor_id),
        event_digest,
        created_at: crate::clock::now_utc()
            .with_nanosecond(0)
            .unwrap_or_else(crate::clock::now_utc),
        domain: None,
        audience: None,
        jws: String::new(),
    };
    let binding_bytes = proof
        .canonical_binding_bytes(&envelope.actor_id)
        .map_err(|err| anyhow::anyhow!("{kind} binding encoding failed: {err}"))?;
    proof.jws = signer
        .detached_jws_over(&binding_bytes)
        .map_err(|err| anyhow::anyhow!("{kind} proof signing failed: {err}"))?;
    envelope.proof = Some(serde_json::to_value(&proof)?);
    Ok(())
}
