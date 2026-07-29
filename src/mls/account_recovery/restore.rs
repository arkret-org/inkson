//! Fetch + restore flow: account secret, MLS history, and the private-plaintext
//! sidecar.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::Verifier as _;
use serde_json::{Value, json};

use super::backup_body::{
    decrypt_mls_account_secret_backup, decrypt_mls_private_plaintext_backup,
    open_mls_account_secret_recovery_public_key_backup,
};
use super::selection::{
    all_mls_account_secret_backups, is_mls_history_backup, mls_account_secret_backup_version,
    select_mls_account_secret_backup, select_mls_account_secret_recovery_public_key_backup,
    select_mls_history_backups, select_mls_private_plaintext_backup,
    select_preferred_mls_account_secret_backup,
};
use super::series::verify_series_chain;

fn is_managed_agent_pcr_history_backup(body: &Value) -> bool {
    body.pointer("/domain_separation/subdomain")
        .and_then(Value::as_str)
        == Some("managed_agent_pcr")
        && body
            .pointer("/encryption/recipient_method")
            .and_then(Value::as_str)
            == Some("recovery_public_key")
}

fn restore_managed_agent_pcr_history_with_recovery_key(
    list_payload: &Value,
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    recovery_private_key: &[u8],
    expected_recovery_policy_ref: (&str, u64),
) -> Result<usize> {
    let Some(body) = select_mls_history_backups(list_payload)
        .into_iter()
        .filter(is_managed_agent_pcr_history_backup)
        .max_by_key(|body| {
            body.get("series_seq")
                .and_then(Value::as_u64)
                .unwrap_or_default()
        })
    else {
        return Ok(0);
    };
    let policy = body
        .get("recovery_policy_ref")
        .ok_or_else(|| anyhow!("managed Agent PCR backup has no recovery_policy_ref"))?;
    if policy.get("policy_id").and_then(Value::as_str) != Some(expected_recovery_policy_ref.0)
        || policy.get("policy_version").and_then(Value::as_u64)
            != Some(expected_recovery_policy_ref.1)
    {
        return Err(anyhow!("managed Agent PCR backup recovery policy mismatch"));
    }
    let opened =
        crate::key_backup::open_recovery_public_key_backup_body(recovery_private_key, &body)?;
    let plaintext: Value = serde_json::from_slice(&opened)
        .map_err(|error| anyhow!("decode managed Agent PCR plaintext keybag: {error}"))?;
    crate::key_backup::validate_key_backup_plaintext_binding(&body, &plaintext)
        .map_err(anyhow::Error::msg)?;

    struct RestoredState {
        realm_id: String,
        group_id: String,
        epoch: u64,
        owner_id: String,
        state_bytes: Vec<u8>,
        salt: [u8; 16],
    }
    let mut decoded = Vec::new();
    for item in plaintext
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("managed Agent PCR plaintext items are missing"))?
    {
        if item.get("item_kind").and_then(Value::as_str) != Some("mls_group_state") {
            continue;
        }
        let realm_id = item
            .get("realm_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("managed recovery MLS item has no realm_id"))?
            .to_owned();
        let group_id = item
            .get("mls_group_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("managed recovery MLS item has no mls_group_id"))?
            .to_owned();
        let epoch = item
            .get("epoch")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("managed recovery MLS item has no epoch"))?;
        let state_bytes = B64
            .decode(
                item.get("secret_b64u")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("managed recovery MLS item has no secret_b64u"))?
                    .as_bytes(),
            )
            .map_err(|error| anyhow!("decode managed recovery MLS state: {error}"))?;
        let record =
            crate::mls::persistence::MlsSnapshotEnvelope::restore_state_record(&state_bytes)
                .map_err(|error| anyhow!("validate managed recovery MLS state record: {error}"))?;
        if record.group_id != group_id || record.epoch != epoch {
            return Err(anyhow!(
                "managed recovery MLS state record metadata does not match its keybag item"
            ));
        }
        let owner_id = if let Some(binding) = item.get("managed_principal_binding") {
            if binding.get("controller_id").and_then(Value::as_str) != Some(actor_id)
                || binding
                    .get("principal_control_realm_id")
                    .and_then(Value::as_str)
                    != Some(realm_id.as_str())
            {
                return Err(anyhow!(
                    "managed recovery binding does not match controller or PCR"
                ));
            }
            binding
                .get("managed_principal_id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("managed recovery binding has no principal id"))?
                .to_owned()
        } else {
            actor_id.to_owned()
        };
        let epoch_floor = crate::mls::runtime::mls_restore_epoch_floor(state_store, &realm_id);
        if epoch < epoch_floor {
            return Err(anyhow!(
                "managed recovery MLS epoch {epoch} is below local floor {epoch_floor} for {realm_id}"
            ));
        }
        let mut salt = [0_u8; 16];
        getrandom::fill(&mut salt)
            .map_err(|error| anyhow!("generate managed recovery snapshot salt: {error}"))?;
        decoded.push(RestoredState {
            realm_id,
            group_id,
            epoch,
            owner_id,
            state_bytes,
            salt,
        });
    }
    if decoded.is_empty() {
        return Err(anyhow!(
            "managed Agent PCR recovery keybag contains no MLS group state"
        ));
    }
    for state in &decoded {
        let secret = crate::mls::runtime::load_or_create_device_snapshot_secret(
            secure_store,
            &state.owner_id,
            device_id,
        )
        .map_err(|error| anyhow!("prepare restored MLS snapshot secret: {error}"))?;
        if state.owner_id != actor_id {
            crate::mls::runtime::mark_account_mls_secret_verified(secure_store, &state.owner_id)
                .map_err(|error| anyhow!("mark restored managed MLS secret verified: {error}"))?;
        }
        let snapshot = crate::mls::persistence::encrypt_state(
            &state.realm_id,
            &state.group_id,
            state.epoch,
            &state.state_bytes,
            &secret,
            &state.salt,
        );
        state_store.save_mls_snapshot(state.realm_id.clone(), snapshot);
    }
    Ok(decoded.len())
}

fn mls_history_backup_needs_restore(
    body: &Value,
    state_store: &crate::state::LocalStateStore,
    local_secret: &str,
) -> bool {
    let Ok(envelope) = crate::mls::runtime::decode_mls_history_backup_envelope(body, local_secret)
    else {
        return false;
    };
    // P0 fork guard: verify the local secret can actually open the SERVER's
    // history ciphertext. A new device's Welcome bootstrap mints a fresh random
    // account/device-snapshot secret when none exists yet, then saves a local
    // snapshot encrypted under that random secret. That local snapshot will
    // always self-decrypt, so testing only the local snapshot (as we did below)
    // cannot tell a genuinely-recovered secret apart from a forked random one.
    // If the local secret fails to decrypt this server backup, the device has
    // forked from the account-secret recovery chain and MUST be prompted to
    // unlock/import before it pollutes the chain with its own history backups.
    // (Backups this same device uploaded under the random secret still decrypt,
    // so we rely on `.any()` across the full server set to catch a sibling
    // device's backup made under the real account secret.)
    if crate::mls::persistence::decrypt_envelope(&envelope, local_secret).is_err() {
        return true;
    }
    let Some(local_snapshot) = state_store.mls_snapshot_for(&envelope.realm_id) else {
        return true;
    };
    if local_snapshot.group_id != envelope.group_id || local_snapshot.epoch < envelope.epoch {
        return true;
    }
    crate::mls::persistence::decrypt_envelope(&local_snapshot, local_secret).is_err()
}

/// Decide whether the app should ask the user for their Recovery Key to unlock
/// MLS history.
///
/// A local account secret alone is not enough readiness proof: an earlier
/// incomplete bootstrap can leave a stale/random local secret without any
/// usable per-Realm MLS snapshot. In that state encrypted writes still fail
/// with `MissingWelcome`, so the prompt must stay available whenever the
/// server has account-secret recovery material and local history is missing,
/// stale, or undecryptable.
pub fn mls_restore_prompt_required(
    list_payload: &Value,
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    device_id: &str,
) -> bool {
    if select_preferred_mls_account_secret_backup(list_payload).is_none() {
        return false;
    }
    // A local secret may have been generated speculatively by fresh-device
    // bootstrap before backup discovery. Presence alone does not prove that it
    // belongs to the server recovery chain. Only a successful upload/import
    // sets the verified marker; until then the server backup must win.
    if !crate::mls::runtime::account_mls_secret_verified(secure_store, actor_id).unwrap_or(false) {
        return true;
    }
    let local_secret =
        crate::mls::runtime::load_device_snapshot_secret(secure_store, actor_id, device_id).ok();
    let Some(local_secret) = local_secret.filter(|secret| !secret.trim().is_empty()) else {
        return true;
    };
    select_mls_history_backups(list_payload)
        .iter()
        .any(|body| mls_history_backup_needs_restore(body, state_store, &local_secret))
}

/// Counts returned by [`auto_restore_mls_history_with_passphrase`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RestoreReport {
    /// Whether the account MLS secret was imported or refreshed from the
    /// server backup on this call.
    pub account_secret_imported: bool,
    /// Number of `mls_history` backups successfully restored into the state store.
    pub restored: usize,
    /// Number of `mls_history` backups that failed to restore.
    pub failed: usize,
    /// X5.3 — whether the encrypted local-plaintext sidecar backup was
    /// successfully decrypted and merged into the local state store on this
    /// call. Stays `false` when no sidecar backup exists or restore of it
    /// failed (a non-fatal condition; see `first_error`).
    pub private_plaintext_restored: bool,
    /// First restore failure reason, for diagnostics.
    pub first_error: Option<String>,
}

fn verify_active_backup_series(list_payload: &Value, backup_kind: &str) -> Result<()> {
    let Some(active_series) =
        super::selection::active_series_id_for_backup_class(list_payload, backup_kind)
    else {
        return Err(anyhow!(
            "{backup_kind} active-series pointer is unavailable"
        ));
    };
    let bodies = super::selection::iter_backup_bodies(list_payload)
        .filter(|body| body.get("backup_kind").and_then(Value::as_str) == Some(backup_kind))
        .filter(|body| body.get("series_id").and_then(Value::as_str) == Some(active_series))
        .cloned()
        .collect::<Vec<_>>();
    let Some(tail) = bodies
        .iter()
        .max_by_key(|body| super::selection::backup_series_seq(body))
    else {
        return Err(anyhow!(
            "authoritative {backup_kind} series has no envelopes"
        ));
    };
    verify_series_chain(tail, &bodies)
}

fn observe_active_series_versions(
    list_payload: &Value,
    state_store: &mut crate::state::LocalStateStore,
    actor_id: &str,
) -> Result<()> {
    for record in list_payload
        .get("active_series")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if record.get("actor_id").and_then(Value::as_str) != Some(actor_id) {
            return Err(anyhow!("active-series actor binding mismatch"));
        }
        let backup_kind = record
            .get("backup_kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("active-series record omitted backup_kind"))?;
        let version = record
            .get("series_pointer_version")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("active-series record omitted series_pointer_version"))?;
        state_store.observe_key_backup_active_series_version(actor_id, backup_kind, version)?;
    }
    Ok(())
}

/// Pure-fetch helper: list the server's key backups and return the
/// preferred `mls_account_secret` body if one is present (None if absent). No
/// Recovery Key is required — this is the SAFE half that can run at silent boot
/// to *detect* whether account-secret recovery is available.
pub async fn fetch_mls_account_secret_backup(
    api: &crate::transport::TransportClient,
    actor_id: &str,
) -> Result<Option<Value>> {
    let payload = fetch_mls_restore_payload(api, actor_id).await?;
    Ok(select_preferred_mls_account_secret_backup(&payload))
}

/// Fetch the full key-backup list once for MLS account-secret import +
/// history restore.
///
/// UI callers that hold a Dioxus `SyncSignal<LocalStateStore>` should call this
/// before acquiring `state_store.write()`, then pass the returned payload into
/// [`restore_mls_history_with_passphrase_from_payload`]. That keeps the local
/// state write guard out of the network await.
pub async fn fetch_mls_restore_payload(
    api: &crate::transport::TransportClient,
    actor_id: &str,
) -> Result<Value> {
    let backups = api
        .list_key_backups()
        .await
        .map_err(|err| anyhow!("list key backups: {err}"))?;
    let mut payload = serde_json::to_value(&backups)?;
    payload["active_series"] =
        Value::Array(fetch_authoritative_active_series(api, actor_id).await?);
    Ok(payload)
}

/// Fresh-device discovery can race the projection of backups uploaded moments
/// earlier by another device. Retry the real LIST read briefly instead of
/// caching the first empty projection for the lifetime of the app session.
pub async fn fetch_mls_restore_payload_after_projection(
    api: &crate::transport::TransportClient,
    actor_id: &str,
) -> Result<Value> {
    let mut payload = fetch_mls_restore_payload(api, actor_id).await?;
    for _ in 0..5 {
        if select_preferred_mls_account_secret_backup(&payload).is_some() {
            break;
        }
        crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(1)).await;
        payload = fetch_mls_restore_payload(api, actor_id).await?;
    }
    Ok(payload)
}

async fn fetch_authoritative_active_series(
    api: &crate::transport::TransportClient,
    actor_id: &str,
) -> Result<Vec<Value>> {
    let actor = arkret_sdk::Did::new(actor_id.to_owned())
        .map_err(|error| anyhow!("invalid backup actor_id: {error}"))?;
    let realm_id = arkret_sdk::principal_control_realm_id(&actor);
    let events = api
        .http()
        .events_query_all_pages(realm_id.as_str())
        .await
        .map_err(|error| anyhow!("read key backup active-series control stream: {error}"))?;
    let mut active_events = events
        .events
        .iter()
        .filter(|event| event.kind.as_str() == "ak.key_backup.active_series")
        .collect::<Vec<_>>();
    if active_events.is_empty() {
        return Ok(Vec::new());
    }
    let viewer = api
        .http()
        .account_viewer()
        .await
        .map_err(|error| anyhow!("read active-series device authority: {error}"))?;
    if viewer.principal_id != actor {
        return Err(anyhow!(
            "active-series device authority belongs to another principal"
        ));
    }
    let device_ids = viewer
        .devices
        .into_iter()
        .map(|device| device.device_id)
        .collect::<Vec<_>>();
    if device_ids.is_empty() {
        return Err(anyhow!(
            "active-series verification has no principal device inventory"
        ));
    }
    let keys = api
        .http()
        .keys_query(&arkret_models_crypto::KeysQueryRequestBody {
            device_keys: BTreeMap::from([(actor.clone(), device_ids)]),
            timeout_ms: None,
        })
        .await
        .map_err(|error| anyhow!("read active-series verification keys: {error}"))?;
    if !keys.failures.is_empty() {
        return Err(anyhow!(
            "active-series verification key query was incomplete"
        ));
    }
    let mut current = BTreeMap::<
        String,
        (
            arkret_sdk::KeyBackupActiveSeriesHead,
            arkret_sdk::KeyBackupActiveSeries,
        ),
    >::new();
    active_events.sort_by_key(|event| event.actor_seq);
    for event in active_events {
        let record = serde_json::from_value::<arkret_sdk::KeyBackupActiveSeries>(
            serde_json::to_value(&event.payload)?,
        )
        .map_err(|error| anyhow!("accepted active-series Event is invalid: {error}"))?;
        if record.actor_id != actor || event.actor_id != actor {
            return Err(anyhow!(
                "accepted active-series Event actor does not match its principal control realm"
            ));
        }
        verify_active_series_record_signature(&record, &keys)?;
        let class = record.backup_kind.as_str().to_owned();
        let head = arkret_sdk::validate_key_backup_active_series_transition(
            current.get(&class).map(|(head, _)| head),
            &record,
        )
        .map_err(|error| anyhow!("accepted active-series chain is not canonical: {error}"))?;
        current.insert(class, (head, record));
    }
    current
        .into_values()
        .map(|(_, record)| serde_json::to_value(record).map_err(anyhow::Error::from))
        .collect()
}

fn verify_active_series_record_signature(
    record: &arkret_sdk::KeyBackupActiveSeries,
    keys: &arkret_models_crypto::KeysQueryOutcome,
) -> Result<()> {
    if record.auth_data.signature_algorithm
        != arkret_models_crypto::KeyBackupSignatureAlgorithm::Ed25519
    {
        return Err(anyhow!(
            "active-series record uses an unsupported signature algorithm"
        ));
    }
    let mut unsigned = serde_json::to_value(record)?;
    unsigned["auth_data"]
        .as_object_mut()
        .ok_or_else(|| anyhow!("active-series auth_data is not an object"))?
        .remove("signature");
    let message = crate::canonical::canonical_json_bytes(&unsigned)?;
    let signature = ed25519_dalek::Signature::from_slice(
        &B64.decode(record.auth_data.signature.as_str())
            .map_err(|error| anyhow!("decode active-series signature: {error}"))?,
    )
    .map_err(|error| anyhow!("parse active-series signature: {error}"))?;
    let devices = keys
        .device_keys
        .get(&record.actor_id)
        .ok_or_else(|| anyhow!("active-series key query omitted its actor"))?;
    let a_generation = keys.cross_signing.get(&record.actor_id);
    let b_generation = keys.device_generations.get(&record.actor_id);
    if a_generation.is_some() == b_generation.is_some() {
        return Err(anyhow!(
            "active-series authority model is absent or conflicted"
        ));
    }
    for (device_id, device) in devices {
        if !device.is_usable_in_generation(b_generation) {
            continue;
        }
        let Some(device_signing_key) = device.device_signing_key.as_ref() else {
            continue;
        };
        let did_key = device_signing_key.as_str();
        let Some(multikey) = did_key.strip_prefix("did:key:") else {
            continue;
        };
        let verification_method = record.auth_data.verification_method.as_str();
        if verification_method != format!("{}#{}", record.actor_id, device_id)
            && verification_method != did_key
            && verification_method != format!("{did_key}#{multikey}")
            && verification_method != format!("{did_key}#device")
        {
            continue;
        }
        let anchored = match (
            &record.auth_data.trust_binding,
            &record.frontier_ref.generation,
        ) {
            (
                arkret_sdk::KeyBackupActiveSeriesTrustBinding::SskGeneration(generation),
                arkret_sdk::KeyBackupActiveSeriesFrontierGeneration::SskGeneration(frontier),
            ) => {
                generation == frontier
                    && a_generation.is_some_and(|publish| {
                        publish.generation == *generation
                            && device
                                .cross_signing_binding
                                .as_ref()
                                .is_some_and(|binding| binding.ssk_generation == generation.get())
                    })
            }
            (
                arkret_sdk::KeyBackupActiveSeriesTrustBinding::DeviceAuthorizeEventId(event_id),
                arkret_sdk::KeyBackupActiveSeriesFrontierGeneration::DeviceGenerationRef(frontier),
            ) => {
                b_generation.is_some_and(|generation| {
                    generation.device_generation_status
                        == arkret_sdk::DeviceGenerationStatus::Active
                        && generation.current_device_generation_ref == *frontier
                }) && device.device_authorize_event_id.as_ref() == Some(event_id)
                    && device.authorized_generation_ref.as_ref() == Some(frontier)
            }
            _ => false,
        };
        if !anchored {
            continue;
        }
        let decoded = arkret_sdk::decode_multibase_base58btc(multikey)
            .map_err(|error| anyhow!("active-series Ed25519 key is invalid: {error}"))?;
        let Some((codec, header_len)) = arkret_sdk::decode_multicodec_varint(&decoded) else {
            continue;
        };
        if codec != 0xed || decoded.len().saturating_sub(header_len) != 32 {
            continue;
        }
        let key_bytes = <[u8; 32]>::try_from(&decoded[header_len..])
            .map_err(|_| anyhow!("active-series Ed25519 key length is invalid"))?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
            .map_err(|error| anyhow!("active-series Ed25519 key is invalid: {error}"))?;
        if verifying_key.verify(&message, &signature).is_ok() {
            return Ok(());
        }
    }
    Err(anyhow!(
        "active-series record signature is not anchored to the current trust generation"
    ))
}

pub async fn fetch_mls_restore_payload_with_unlock_proof(
    api: &crate::transport::TransportClient,
    actor_id: &str,
    device_id: &str,
) -> Result<Value> {
    let payload = fetch_mls_restore_payload(api, actor_id).await?;
    hydrate_mls_restore_payload_with_unlock_proof(api, payload, actor_id, device_id, None).await
}

pub async fn fetch_mls_restore_payload_with_recovery_session_unlock_proof(
    api: &crate::transport::TransportClient,
    actor_id: &str,
    device_id: &str,
    recovery_session: &arkret_sdk::RecoverySessionState,
) -> Result<Value> {
    let payload = fetch_mls_restore_payload_after_projection(api, actor_id).await?;
    hydrate_mls_restore_payload_with_unlock_proof(
        api,
        payload,
        actor_id,
        device_id,
        Some(recovery_session),
    )
    .await
}

async fn hydrate_mls_restore_payload_with_unlock_proof(
    api: &crate::transport::TransportClient,
    payload: Value,
    actor_id: &str,
    device_id: &str,
    recovery_session: Option<&arkret_sdk::RecoverySessionState>,
) -> Result<Value> {
    let mut full_backups = Vec::new();
    for entry in payload
        .get("backups")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let backup_id = entry
            .get("backup_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let backup_kind = entry
            .get("backup_kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if matches!(
            backup_kind,
            "secret_storage" | "mls_history" | "did_recovery"
        ) {
            let active_series =
                super::selection::active_series_id_for_backup_class(&payload, backup_kind);
            if entry.get("series_id").and_then(Value::as_str) != active_series {
                continue;
            }
        }
        if entry.get("ciphertext").and_then(Value::as_str).is_some() {
            full_backups.push(entry);
            continue;
        }
        if !matches!(
            backup_kind,
            "secret_storage" | "mls_history" | "did_recovery"
        ) {
            full_backups.push(entry);
            continue;
        }
        let backup_id = if backup_id.is_empty() {
            "(unknown)"
        } else {
            backup_id.as_str()
        };
        let full = match recovery_session {
            Some(session) => {
                crate::key_backup::fetch_key_backup_with_recovery_session_unlock_proof(
                    api, &entry, actor_id, device_id, session,
                )
                .await
            }
            None => {
                crate::key_backup::fetch_key_backup_with_active_unlock_proof(
                    api, &entry, actor_id, device_id,
                )
                .await
            }
        }
        .map_err(|err| anyhow!("fetch key backup {backup_id} with unlock proof: {err}"))?;
        full_backups.push(full);
    }
    let full_payload = json!({
        "backups": full_backups,
        "active_series": payload.get("active_series").cloned().unwrap_or_else(|| json!([])),
        "next_cursor": payload.get("next_cursor").cloned().unwrap_or(Value::Null),
        "has_more": false,
        "state": payload.get("state").cloned().unwrap_or_else(|| json!("active")),
    });
    Ok(full_payload)
}

/// Hydrate the complete active MLS-history series needed by the silent
/// already-unlocked-device restore path.
///
/// The list endpoint intentionally returns metadata-only summaries. Passing
/// those summaries to the envelope decoder produces a misleading missing-AEAD
/// error. This helper replaces eligible history summaries with full envelopes
/// obtained through the standard unlock-proof endpoint while leaving account
/// recovery metadata available for prompt selection. Every active chain link
/// is fetched so `supersedes_digest` can be verified locally before any tail is
/// used.
pub async fn fetch_mls_history_restore_payload_with_unlock_proof(
    api: &crate::transport::TransportClient,
    list_payload: &Value,
    actor_id: &str,
    device_id: &str,
) -> Result<Value> {
    let mut backups = Vec::new();
    for entry in list_payload
        .get("backups")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        if !is_mls_history_backup(&entry) {
            backups.push(entry);
            continue;
        }
        let active_series = super::selection::active_series_id_for_backup_class(
            list_payload,
            crate::key_backup::BackupKind::MlsHistory.as_str(),
        );
        if entry.get("series_id").and_then(Value::as_str) != active_series {
            continue;
        }
        let backup_id = entry
            .get("backup_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("mls_history backup metadata is missing backup_id"))?;
        if entry.get("ciphertext").and_then(Value::as_str).is_some() {
            backups.push(entry);
            continue;
        }
        let full = crate::key_backup::fetch_key_backup_with_active_unlock_proof(
            api, &entry, actor_id, device_id,
        )
        .await
        .map_err(|err| anyhow!("fetch MLS history backup {backup_id} with unlock proof: {err}"))?;
        backups.push(full);
    }

    let mut payload = list_payload.clone();
    payload["backups"] = Value::Array(backups);
    Ok(payload)
}

/// Restore MLS account secret + history from an already-fetched
/// `list_key_backups` payload.
///
/// This function is deliberately synchronous: it can run inside a short
/// `state_store.write()` critical section after all network awaits have
/// completed.
pub fn restore_mls_history_with_passphrase_from_payload(
    list_payload: &Value,
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    passphrase: &[u8],
) -> Result<RestoreReport> {
    let mut report = RestoreReport::default();
    observe_active_series_versions(list_payload, state_store, actor_id)?;

    // Step 1: refresh the local account secret from the server backup when it
    // exists. This deliberately runs even if a local secret is present: a
    // previous incomplete bootstrap may have generated a stale/random secret,
    // which would make every history restore fail with a secret mismatch.
    let has_local_secret =
        crate::mls::runtime::load_device_snapshot_secret(secure_store, actor_id, device_id).is_ok();
    if let Some(secret_body) = select_mls_account_secret_backup(list_payload) {
        // Fail closed against series rollback / withholding: the selected tail
        // must sit at the end of a complete, digest-linked chain back to genesis
        // before we trust it as the account secret to import.
        verify_series_chain(&secret_body, &all_mls_account_secret_backups(list_payload))?;
        let secret_bytes = decrypt_mls_account_secret_backup(passphrase, &secret_body)?;
        let secret = String::from_utf8(secret_bytes)
            .map_err(|err| anyhow!("account secret is not valid UTF-8: {err}"))?;
        let version = mls_account_secret_backup_version(&secret_body);
        crate::mls::runtime::replace_account_mls_secret_version(
            secure_store,
            actor_id,
            version,
            &secret,
        )
        .map_err(|err| anyhow!("replace account MLS secret: {err}"))?;
        crate::mls::runtime::mark_account_mls_secret_verified(secure_store, actor_id)
            .map_err(|err| anyhow!("mark restored account MLS secret verified: {err}"))?;
        report.account_secret_imported = true;
    } else if !has_local_secret {
        return Err(anyhow!(
            "no mls_account_secret backup on server; cannot recover MLS history"
        ));
    }
    if !select_mls_history_backups(list_payload).is_empty() {
        verify_active_backup_series(
            list_payload,
            crate::key_backup::BackupKind::MlsHistory.as_str(),
        )?;
    }

    restore_history_and_sidecar(
        list_payload,
        state_store,
        secure_store,
        actor_id,
        device_id,
        &mut report,
    );
    Ok(report)
}

/// A3 (key-management.md §7.5.2): fresh-device restore via the recovery PRIVATE
/// key (no passphrase prompt). Opens the HPKE `recovery_public_key`
/// account-secret backup, imports the secret, then restores history + sidecar
/// — the passphrase-free counterpart of
/// [`restore_mls_history_with_passphrase_from_payload`]. The recovery private
/// key is the one unlocked by the recovery policy (saved recovery key /
/// threshold / hardware); on a brand-new browser (empty secure store) this is
/// the path that works without first holding the account secret.
pub fn restore_mls_history_with_recovery_key_from_payload(
    list_payload: &Value,
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    recovery_private_key: &[u8],
    expected_recovery_policy_ref: (&str, u64),
) -> Result<RestoreReport> {
    let _ = device_id;
    let mut report = RestoreReport::default();
    observe_active_series_versions(list_payload, state_store, actor_id)?;
    verify_active_backup_series(
        list_payload,
        crate::key_backup::BackupKind::SecretStorage.as_str(),
    )?;
    if !select_mls_history_backups(list_payload).is_empty() {
        verify_active_backup_series(
            list_payload,
            crate::key_backup::BackupKind::MlsHistory.as_str(),
        )?;
    }
    let secret_body = select_mls_account_secret_recovery_public_key_backup(list_payload)
        .ok_or_else(|| anyhow!("no recovery_public_key account-secret backup on server"))?;
    let (secret, version) = open_mls_account_secret_recovery_public_key_backup(
        recovery_private_key,
        &secret_body,
        expected_recovery_policy_ref,
    )?;
    crate::mls::runtime::replace_account_mls_secret_version(
        secure_store,
        actor_id,
        version,
        &secret,
    )
    .map_err(|err| anyhow!("replace account MLS secret: {err}"))?;
    crate::mls::runtime::mark_account_mls_secret_verified(secure_store, actor_id)
        .map_err(|err| anyhow!("mark restored account MLS secret verified: {err}"))?;
    report.account_secret_imported = true;
    report.restored += restore_managed_agent_pcr_history_with_recovery_key(
        list_payload,
        state_store,
        secure_store,
        actor_id,
        device_id,
        recovery_private_key,
        expected_recovery_policy_ref,
    )?;

    restore_history_and_sidecar(
        list_payload,
        state_store,
        secure_store,
        actor_id,
        device_id,
        &mut report,
    );
    Ok(report)
}

/// Restore server-side MLS history using the account/device snapshot secret
/// that is already present on this device. This is the no-prompt path for an
/// unlocked device whose local snapshot is stale relative to another device's
/// uploaded `mls_history` backup.
pub fn restore_mls_history_with_local_secret_from_payload(
    list_payload: &Value,
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    device_id: &str,
) -> RestoreReport {
    let mut report = RestoreReport::default();
    if let Err(error) = observe_active_series_versions(list_payload, state_store, actor_id) {
        report.failed = 1;
        report.first_error = Some(error.to_string());
        return report;
    }
    if !select_mls_history_backups(list_payload).is_empty()
        && let Err(error) = verify_active_backup_series(
            list_payload,
            crate::key_backup::BackupKind::MlsHistory.as_str(),
        )
    {
        report.failed = 1;
        report.first_error = Some(error.to_string());
        return report;
    }
    restore_history_and_sidecar(
        list_payload,
        state_store,
        secure_store,
        actor_id,
        device_id,
        &mut report,
    );
    report
}

/// Shared restore tail (used by both the passphrase and recovery-key entry
/// points): with the account secret already local, restore every `mls_history`
/// backup and the author's `mls_private_plaintext` sidecar. Per-item failures
/// are counted, never abort the rest.
fn restore_history_and_sidecar(
    list_payload: &Value,
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    report: &mut RestoreReport,
) {
    for body in select_mls_history_backups(list_payload)
        .into_iter()
        .filter(|body| !is_managed_agent_pcr_history_backup(body))
    {
        match crate::mls::runtime::restore_mls_history_backup_with_device_snapshot(
            state_store,
            secure_store,
            actor_id,
            device_id,
            &body,
        ) {
            Ok(_) => report.restored += 1,
            Err(err) => {
                report.failed += 1;
                if report.first_error.is_none() {
                    report.first_error = Some(err.user_message());
                }
            }
        }
    }

    if let Some(sidecar_body) = select_mls_private_plaintext_backup(list_payload) {
        match restore_private_plaintext_sidecar(&sidecar_body, state_store, secure_store, actor_id)
        {
            Ok(()) => report.private_plaintext_restored = true,
            Err(err) => {
                if report.first_error.is_none() {
                    report.first_error = Some(format!("private plaintext restore: {err}"));
                }
            }
        }
    }
}

/// X5.3 — decrypt the `mls_private_plaintext` sidecar backup with the local
/// account secret and merge it into `state_store`. Factored out so the restore
/// step stays readable and so the `?` short-circuit doesn't abort the whole
/// restore.
fn restore_private_plaintext_sidecar(
    sidecar_body: &Value,
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
) -> Result<()> {
    let stored = crate::mls::runtime::load_account_mls_secret(secure_store, actor_id)
        .map_err(|err| anyhow!("load account MLS secret: {err}"))?
        .ok_or_else(|| anyhow!("no account secret available to decrypt sidecar"))?;
    let sidecar_json =
        decrypt_mls_private_plaintext_backup(stored.secret.as_bytes(), sidecar_body)?;
    let map: std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
    > = serde_json::from_slice(&sidecar_json)
        .map_err(|err| anyhow!("parse sidecar JSON: {err}"))?;
    state_store.merge_private_plaintext_map(map);
    Ok(())
}

/// Auto-restore MLS history for a fresh device using the recovery passphrase.
///
/// Strand:
///   1. Fetch the server's `mls_account_secret` backup when present, decrypt it with `passphrase`,
///      and replace the local account key with it. This also repairs stale local secrets left by
///      incomplete bootstraps.
///   2. List every `mls_history` backup and restore each one via
///      [`crate::mls::runtime::restore_mls_history_backup_with_device_snapshot`].
///
/// This is the function the recovery UI / a future "unlock MLS" prompt calls
/// once the user has supplied the passphrase. Returns per-backup counts.
pub async fn auto_restore_mls_history_with_passphrase(
    api: &crate::transport::TransportClient,
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    passphrase: &[u8],
) -> Result<RestoreReport> {
    // List once and reuse for both the account-secret and history selection.
    let payload = fetch_mls_restore_payload_with_unlock_proof(api, actor_id, device_id).await?;
    restore_mls_history_with_passphrase_from_payload(
        &payload,
        state_store,
        secure_store,
        actor_id,
        device_id,
        passphrase,
    )
}

/// Decide whether the app should prompt the user to set a recovery passphrase
/// and back up their account MLS secret.
///
/// This is the mirror of [`mls_restore_prompt_required`]: it fires when the
/// user HAS used encryption (a local account MLS secret exists) but the server
/// holds NO `mls_account_secret` backup yet, so switching browsers would lose
/// their history. Normal users never reach the explicit recovery-setup screen,
/// so without this nudge their account secret stays purely local.
///
/// Returns `false` when a server backup already exists (nothing to do), and
/// `false` when there is no local account secret (the user never used
/// encryption — don't nag).
pub fn mls_backup_prompt_required(
    list_payload: &Value,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    device_id: &str,
) -> bool {
    let _ = device_id;
    if select_preferred_mls_account_secret_backup(list_payload).is_some() {
        return false;
    }
    matches!(
        crate::mls::runtime::load_account_mls_secret(secure_store, actor_id),
        Ok(Some(_))
    )
}
