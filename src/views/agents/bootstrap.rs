//! Controller-side Agent PCR bootstrap and managed recovery publication.

use std::collections::BTreeSet;
use std::time::Duration;

use arkret_models_collaboration::agent_operations::AgentPcrRecoveryState;
use arkret_models_crypto::{KeyBackupContentItem, ManagedFrontierRef, ManagedPrincipalBinding};
use arkret_wire::SchemaId;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use dioxus::prelude::{ReadableExt, SyncSignal, WritableExt};
use serde_json::{Value, json};

use crate::operation::{EventKind, OperationBuilder, uuid_v7};
use crate::state::LocalStateStore;

const PCR_RECOVERY_PROJECTION_WAIT_ATTEMPTS: usize = 18;
const ACTIVE_SERIES_SIGNED_FIELDS: &[&str] = &[
    "schema",
    "actor_id",
    "backup_kind",
    "active_series_id",
    "series_pointer_version",
    "previous_series_ids",
    "frontier_ref",
    "issued_at",
];

#[derive(Clone)]
struct ManagedPcrBackupItem {
    snapshot: crate::mls::persistence::MlsSnapshotEnvelope,
    state_bytes: Vec<u8>,
    binding: Option<ManagedPrincipalBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MlsHistoryActiveSeries {
    series_id: String,
    pointer_version: u64,
    previous_series_ids: Vec<String>,
}

struct MlsHistorySeriesTarget {
    series_id: String,
    series_seq: u64,
    previous_tail: Option<Value>,
    publish_pointer: Option<(u64, Vec<String>)>,
}

enum MlsHistoryRecoveryPlan {
    Reuse {
        backup_id: String,
        series_id: String,
        publish_pointer: Option<(u64, Vec<String>)>,
    },
    Write(MlsHistorySeriesTarget),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ControllerBackupTrustAnchor {
    SskGeneration(u64),
    DeviceGeneration {
        authorize_event_id: String,
        generation_ref: String,
    },
}

async fn current_controller_backup_trust_anchor(
    http: &arkret_sdk::http_client::Client,
    controller_id: &str,
    device_id: &str,
) -> anyhow::Result<ControllerBackupTrustAnchor> {
    let controller = arkret_sdk::Did::new(controller_id.to_owned())?;
    let device = arkret_sdk::DeviceId::new(device_id.to_owned())?;
    let outcome = crate::transport::keys::query_keys(http, controller_id, device_id).await?;
    let record = outcome
        .device_keys
        .get(&controller)
        .and_then(|devices| devices.get(&device))
        .ok_or_else(|| anyhow::anyhow!("active controller device is absent from keys/query"))?;
    let generation = outcome.device_generations.get(&controller);
    if !record.is_usable_in_generation(generation) {
        anyhow::bail!("active controller device is not usable in the current trust generation");
    }
    match (
        record.cross_signing_binding.as_ref(),
        generation,
        record.authorized_generation_ref.as_ref(),
        record.device_authorize_event_id.as_ref(),
    ) {
        (Some(binding), None, None, _) => {
            let publish = outcome.cross_signing.get(&controller).ok_or_else(|| {
                anyhow::anyhow!("keys/query omitted the current cross-signing publish")
            })?;
            if publish.generation.get() != binding.ssk_generation {
                anyhow::bail!("device binding generation differs from the current SSK generation");
            }
            Ok(ControllerBackupTrustAnchor::SskGeneration(
                binding.ssk_generation,
            ))
        }
        (None, Some(generation), Some(device_generation), Some(authorize_event_id))
            if generation.device_generation_status
                == arkret_sdk::DeviceGenerationStatus::Active
                && device_generation.as_str()
                    == generation.current_device_generation_ref.as_str() =>
        {
            Ok(ControllerBackupTrustAnchor::DeviceGeneration {
                authorize_event_id: authorize_event_id.to_string(),
                generation_ref: generation.current_device_generation_ref.to_string(),
            })
        }
        _ => anyhow::bail!("active controller device trust model is mixed or incomplete"),
    }
}

pub(crate) fn controller_signer_device_id(
    controller_id: &str,
    signer: &crate::event_signer::InksonEventSigner,
    signer_account_scope: Option<&str>,
) -> anyhow::Result<String> {
    let normalized_scope = signer_account_scope
        .map(str::trim)
        .filter(|scope| !scope.is_empty());
    let signer_binding_matches = match normalized_scope {
        Some(scope) => scope == controller_id,
        None => signer.signer_did() == controller_id,
    };
    if !signer_binding_matches {
        anyhow::bail!(
            "active signer is not bound to controller {} (signer DID: {}, account scope: {})",
            controller_id,
            signer.signer_did(),
            normalized_scope.unwrap_or("unavailable")
        );
    }
    signer
        .device_id()
        .filter(|device| !device.trim().is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow::anyhow!("active controller device id is unavailable"))
}

fn managed_agent_initial_seal_required(error: &anyhow::Error) -> bool {
    crate::api_error::is_realm_seal_frontier_pending_error(error)
}

/// True when an Agent provably has nothing to contribute to the shared managed
/// recovery series because its own PCR bootstrap never completed.
///
/// Both halves are required, and both come from the Principal Server rather
/// than from local state: the recovery projection is still `Pending` (no series
/// was ever published for this Agent) and the Realm Seal frontier reports no
/// accepted device-signed Seal. Together they mean there is no frontier to bind
/// and no recoverable state to drop. A `Ready` / `Stale` Agent, or a `Pending`
/// one whose frontier failed for any other reason, MUST keep failing closed —
/// excluding either would silently narrow recovery coverage.
fn managed_pcr_setup_never_completed(
    recovery: &AgentPcrRecoveryState,
    error: &anyhow::Error,
) -> bool {
    matches!(recovery, AgentPcrRecoveryState::Pending) && managed_agent_initial_seal_required(error)
}

fn next_mls_history_pointer(
    current: Option<&MlsHistoryActiveSeries>,
    orphaned_series_ids: impl IntoIterator<Item = String>,
) -> anyhow::Result<(u64, Vec<String>)> {
    let Some(current) = current else {
        let previous = orphaned_series_ids.into_iter().collect::<BTreeSet<_>>();
        return Ok((1, previous.into_iter().collect()));
    };
    let version = current
        .pointer_version
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("mls_history active-series pointer version overflow"))?;
    let mut previous = current
        .previous_series_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    previous.insert(current.series_id.clone());
    for series_id in orphaned_series_ids {
        previous.insert(series_id);
    }
    Ok((version, previous.into_iter().collect()))
}

async fn current_mls_history_active_series(
    submitter: &crate::event_submit::EventSubmitter,
    controller_id: &str,
    highest_seen: Option<u64>,
) -> anyhow::Result<Option<MlsHistoryActiveSeries>> {
    let controller = arkret_sdk::Did::new(controller_id.to_owned())?;
    let realm_id = arkret_sdk::principal_control_realm_id(&controller);
    let backfill = submitter.backfill(realm_id.as_str()).await?;
    let mut current = None::<arkret_sdk::KeyBackupActiveSeriesHead>;
    for event in backfill
        .events
        .iter()
        .filter(|event| event.kind.as_str() == "ak.key_backup.active_series")
    {
        let record = serde_json::from_value::<arkret_sdk::KeyBackupActiveSeries>(
            serde_json::to_value(&event.payload)?,
        )
        .map_err(|error| anyhow::anyhow!("accepted active-series Event is invalid: {error}"))?;
        if record.actor_id.as_str() != controller_id
            || record.backup_kind != crate::key_backup::BackupKind::MlsHistory
        {
            continue;
        }
        current = Some(
            arkret_sdk::validate_key_backup_active_series_transition(current.as_ref(), &record)
                .map_err(|error| {
                    anyhow::anyhow!("accepted active-series chain is not canonical: {error}")
                })?,
        );
    }
    if highest_seen.is_some_and(|highest| {
        current
            .as_ref()
            .map(|head| head.series_pointer_version)
            .unwrap_or_default()
            < highest
    }) {
        anyhow::bail!("backup_frontier_stale");
    }
    Ok(current.map(|head| MlsHistoryActiveSeries {
        series_id: head.active_series_id.to_string(),
        pointer_version: head.series_pointer_version,
        previous_series_ids: head
            .previous_series_ids
            .iter()
            .map(ToString::to_string)
            .collect(),
    }))
}

fn recovery_policy_matches(backup: &Value, recovery_policy_ref: (&str, u64)) -> bool {
    backup.get("recovery_policy_ref").is_some_and(|reference| {
        reference.get("policy_id").and_then(Value::as_str) == Some(recovery_policy_ref.0)
            && reference.get("policy_version").and_then(Value::as_u64)
                == Some(recovery_policy_ref.1)
    })
}

fn backup_contains_managed_pcr_items(backup: &Value) -> bool {
    backup
        .get("contents")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|item| item.get("managed_principal_binding").is_some())
}

fn backup_contains_exact_managed_binding(
    backup: &Value,
    expected: &ManagedPrincipalBinding,
) -> bool {
    backup
        .get("contents")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("managed_principal_binding"))
        .filter_map(|binding| {
            serde_json::from_value::<ManagedPrincipalBinding>(binding.clone()).ok()
        })
        .any(|binding| &binding == expected)
}

async fn resolve_mls_history_series_target(
    api: &crate::transport::TransportClient,
    list_payload: &Value,
    current: Option<MlsHistoryActiveSeries>,
    controller_id: &str,
    device_id: &str,
    recovery_policy_ref: (&str, u64),
    expected_binding: &ManagedPrincipalBinding,
) -> anyhow::Result<MlsHistoryRecoveryPlan> {
    if list_payload
        .get("has_more")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        anyhow::bail!(
            "key-backup list is paginated; refusing to construct an incomplete mls_history tail"
        );
    }
    let mls_backups = list_payload
        .get("backups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|body| body.get("backup_kind").and_then(Value::as_str) == Some("mls_history"))
        .collect::<Vec<_>>();
    let known_series_ids = mls_backups
        .iter()
        .filter_map(|body| body.get("series_id").and_then(Value::as_str))
        .filter(|series_id| !series_id.is_empty())
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();

    let mut exact_tails = mls_backups
        .iter()
        .copied()
        .filter(|backup| {
            recovery_policy_matches(backup, recovery_policy_ref)
                && backup_contains_exact_managed_binding(backup, expected_binding)
        })
        .collect::<Vec<_>>();
    exact_tails.sort_by(|left, right| {
        left.get("created_at")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .cmp(
                right
                    .get("created_at")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            )
            .then_with(|| {
                left.get("series_seq")
                    .and_then(Value::as_u64)
                    .unwrap_or_default()
                    .cmp(
                        &right
                            .get("series_seq")
                            .and_then(Value::as_u64)
                            .unwrap_or_default(),
                    )
            })
            .then_with(|| {
                left.get("backup_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .cmp(
                        right
                            .get("backup_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                    )
            })
    });
    exact_tails.retain(|candidate| {
        let series_id = candidate.get("series_id").and_then(Value::as_str);
        let sequence = candidate.get("series_seq").and_then(Value::as_u64);
        mls_backups.iter().all(|other| {
            other.get("series_id").and_then(Value::as_str) != series_id
                || other.get("series_seq").and_then(Value::as_u64) <= sequence
        })
    });

    if let Some(current) = current.as_ref()
        && let Some(tail) = exact_tails.iter().rev().find(|backup| {
            backup.get("series_id").and_then(Value::as_str) == Some(current.series_id.as_str())
        })
    {
        let backup_id = tail
            .get("backup_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("active mls_history tail omitted backup_id"))?;
        return Ok(MlsHistoryRecoveryPlan::Reuse {
            backup_id: backup_id.to_owned(),
            series_id: current.series_id.clone(),
            publish_pointer: None,
        });
    }

    let orphan_tails = exact_tails
        .iter()
        .filter(|backup| {
            current.as_ref().is_none_or(|active| {
                backup.get("series_id").and_then(Value::as_str) != Some(active.series_id.as_str())
            })
        })
        .collect::<Vec<_>>();
    if orphan_tails.len() > 1 {
        anyhow::bail!(
            "multiple unpublished mls_history attempts cover the same managed frontier; refusing to infer a canonical series from timestamps"
        );
    }
    if let Some(orphan) = orphan_tails.first() {
        let backup_id = orphan
            .get("backup_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("reusable mls_history tail omitted backup_id"))?;
        let series_id = orphan
            .get("series_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("reusable mls_history tail omitted series_id"))?;
        let other_series = known_series_ids
            .iter()
            .filter(|known| known.as_str() != series_id)
            .cloned();
        let (pointer_version, previous_series_ids) =
            next_mls_history_pointer(current.as_ref(), other_series)?;
        return Ok(MlsHistoryRecoveryPlan::Reuse {
            backup_id: backup_id.to_owned(),
            series_id: series_id.to_owned(),
            publish_pointer: Some((pointer_version, previous_series_ids)),
        });
    }

    let Some(current) = current else {
        let (pointer_version, previous_series_ids) =
            next_mls_history_pointer(None, known_series_ids)?;
        return Ok(MlsHistoryRecoveryPlan::Write(MlsHistorySeriesTarget {
            series_id: format!("ak:backup_series:{}", uuid_v7()),
            series_seq: 0,
            previous_tail: None,
            publish_pointer: Some((pointer_version, previous_series_ids)),
        }));
    };
    let tail_metadata = mls_backups
        .into_iter()
        .filter(|body| {
            body.get("series_id").and_then(Value::as_str) == Some(current.series_id.as_str())
        })
        .max_by_key(|body| {
            body.get("series_seq")
                .and_then(Value::as_u64)
                .unwrap_or_default()
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "active mls_history series {} has no visible tail",
                current.series_id
            )
        })?;

    if backup_contains_managed_pcr_items(tail_metadata)
        && !recovery_policy_matches(tail_metadata, recovery_policy_ref)
    {
        let (pointer_version, previous_series_ids) =
            next_mls_history_pointer(Some(&current), known_series_ids)?;
        return Ok(MlsHistoryRecoveryPlan::Write(MlsHistorySeriesTarget {
            series_id: format!("ak:backup_series:{}", uuid_v7()),
            series_seq: 0,
            previous_tail: None,
            publish_pointer: Some((pointer_version, previous_series_ids)),
        }));
    }

    let tail = if tail_metadata
        .get("ciphertext")
        .and_then(Value::as_str)
        .is_some_and(|ciphertext| !ciphertext.is_empty())
    {
        tail_metadata.clone()
    } else {
        let signer = crate::event_signer::active_signer();
        crate::key_backup::fetch_key_backup_with_device_unlock_proof(
            api,
            tail_metadata,
            controller_id,
            device_id,
            signer.as_ref(),
        )
        .await?
    };
    let series_seq = tail
        .get("series_seq")
        .and_then(Value::as_u64)
        .unwrap_or_default()
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("mls_history series sequence overflow"))?;
    Ok(MlsHistoryRecoveryPlan::Write(MlsHistorySeriesTarget {
        series_id: current.series_id,
        series_seq,
        previous_tail: Some(tail),
        publish_pointer: None,
    }))
}

fn build_managed_pcr_backup_body(
    items: &[ManagedPcrBackupItem],
    envelope_frontier: &ManagedFrontierRef,
    controller_id: &str,
    device_id: &str,
    recovery_public_key: &[u8],
    recovery_key_ref: &str,
    recovery_policy_ref: (&str, u64),
    backup_id: &str,
    series_id: &str,
    series_seq: u64,
    previous_series_tail: Option<&Value>,
    trust_anchor: &ControllerBackupTrustAnchor,
    signer: crate::key_backup::KeyBackupSigner<'_>,
) -> anyhow::Result<Value> {
    if items.is_empty() {
        anyhow::bail!("managed Agent PCR backup requires at least one current Agent item");
    }
    let plaintext_items = items
        .iter()
        .map(|item| {
            let mut plaintext_item = json!({
                "item_kind": "mls_group_state",
                "secret_id": "inkson_managed_agent_pcr_snapshot",
                "secret_b64u": B64.encode(&item.state_bytes),
                "realm_id": item.snapshot.realm_id,
                "mls_group_id": item.snapshot.group_id,
                "epoch": item.snapshot.epoch
            });
            if let Some(binding) = &item.binding {
                plaintext_item["managed_principal_binding"] = json!(binding);
            }
            plaintext_item
        })
        .collect::<Vec<_>>();
    let plaintext = json!({
        "schema": SchemaId::KEY_BACKUP_PLAINTEXT_V1,
        "backup_id": backup_id,
        "backup_kind": "mls_history",
        "series_id": series_id,
        "series_seq": series_seq,
        "items": plaintext_items
    });
    let plaintext_bytes = crate::canonical::canonical_json_bytes(&plaintext)?;
    let contents = items
        .iter()
        .map(|item| {
            Ok(KeyBackupContentItem {
                item_kind: "mls_group_state".to_owned(),
                realm_id: Some(arkret_sdk::RealmId::new(item.snapshot.realm_id.clone())?),
                managed_principal_binding: item.binding.clone(),
                mls_group_id: Some(item.snapshot.group_id.clone()),
                epoch: Some(item.snapshot.epoch),
                ..Default::default()
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut body = crate::key_backup::build_recovery_public_key_backup_body_for_items_in_series(
        backup_id,
        controller_id,
        device_id,
        recovery_public_key,
        recovery_key_ref,
        crate::key_backup::BackupKind::MlsHistory,
        "managed_agent_pcr",
        &contents,
        &plaintext_bytes,
        Some(recovery_policy_ref),
        Some(series_id),
        previous_series_tail,
        None,
    )?;
    body["frontier_ref"] = json!({
        "frontier_digest": envelope_frontier.frontier_digest,
        "seal_ref": envelope_frontier.seal_ref
    });
    let auth_anchor = match trust_anchor {
        ControllerBackupTrustAnchor::SskGeneration(generation) => {
            body["frontier_ref"]["ssk_generation"] = json!(generation);
            crate::key_backup::KeyBackupDeviceTrustAnchor::SskGeneration(*generation)
        }
        ControllerBackupTrustAnchor::DeviceGeneration {
            authorize_event_id,
            generation_ref,
        } => {
            body["frontier_ref"]["device_generation_ref"] = json!(generation_ref);
            crate::key_backup::KeyBackupDeviceTrustAnchor::DeviceAuthorizeEventId(
                authorize_event_id.clone(),
            )
        }
    };
    crate::key_backup::validate_key_backup_plaintext_binding(&body, &plaintext)
        .map_err(anyhow::Error::msg)?;
    crate::key_backup::sign_key_backup_with_device_and_trust_anchor(
        &mut body,
        device_id,
        signer,
        Some(auth_anchor),
    )?;
    Ok(body)
}

fn current_controller_backup_hpke_key_ref(
    active_policy: &crate::recovery_strand::ActiveRecoveryPolicy,
    controller_id: &str,
    recovery_public_key: &[u8],
    evaluated_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<String> {
    let policy = active_policy.policy.as_ref().ok_or_else(|| {
        anyhow::anyhow!("active controller recovery policy omitted its signed key configuration")
    })?;
    policy.validate()?;
    if active_policy.principal_id.as_str() != controller_id
        || policy.principal_id != active_policy.principal_id
        || policy.policy_id != active_policy.policy_id
        || policy.version != active_policy.version
    {
        anyhow::bail!("active controller recovery policy summary differs from its signed body");
    }
    let matches = policy
        .recovery_key_agreements
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|entry| {
            entry.usage == arkret_models_crypto::RecoveryKeyAgreementUse::BackupHpke
                && entry.revoked_at.is_none()
                && entry.not_before <= evaluated_at
                && entry.expires_at > evaluated_at
                && entry
                    .hpke_suites
                    .contains(&arkret_models_crypto::RecoveryHpkeSuite::X25519ChaCha20Poly1305)
        })
        .filter_map(|entry| {
            let encoded =
                arkret_sdk::decode_multibase_base58btc(entry.public_key_multibase.as_str()).ok()?;
            let (codec, header_len) = arkret_sdk::decode_multicodec_varint(&encoded)?;
            (codec == 0xec && encoded.get(header_len..) == Some(recovery_public_key))
                .then_some(entry.key_agreement_ref.as_str().to_owned())
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [recipient] => Ok(recipient.clone()),
        [] => anyhow::bail!(
            "local Recovery Key does not match a current backup HPKE key agreement in the active controller recovery policy"
        ),
        _ => anyhow::bail!(
            "active controller recovery policy ambiguously maps the local Recovery Key to multiple backup HPKE key agreements"
        ),
    }
}

fn build_active_mls_history_series_event(
    controller_id: &str,
    series_id: &str,
    pointer_version: u64,
    previous_series_ids: &[String],
    frontier: &arkret_sdk::RealmSealFrontierView,
    trust_anchor: &ControllerBackupTrustAnchor,
) -> anyhow::Result<arkret_sdk::Event> {
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active controller signer is required"))?;
    let verification_method =
        principal_bound_active_series_verification_method(controller_id, signer.as_ref())?;
    let issued_at = arkret_sdk::canonical::format_timestamp_canonical(crate::clock::now_utc());
    let mut payload = json!({
        "schema": SchemaId::KEY_BACKUP_ACTIVE_SERIES_V1,
        "actor_id": controller_id,
        "backup_kind": "mls_history",
        "active_series_id": series_id,
        "series_pointer_version": pointer_version,
        "previous_series_ids": previous_series_ids,
        "frontier_ref": {
            "frontier_digest": frontier.control_event_set_root,
            "seal_ref": frontier.seal_id
        },
        "issued_at": issued_at,
        "auth_data": {
            "verification_method": verification_method,
            "signature_algorithm": "Ed25519",
            "signature": "pending",
            "signed_fields": ACTIVE_SERIES_SIGNED_FIELDS
        }
    });
    match trust_anchor {
        ControllerBackupTrustAnchor::SskGeneration(generation) => {
            payload["frontier_ref"]["ssk_generation"] = json!(generation);
            payload["auth_data"]["ssk_generation"] = json!(generation);
        }
        ControllerBackupTrustAnchor::DeviceGeneration {
            authorize_event_id,
            generation_ref,
        } => {
            payload["frontier_ref"]["device_generation_ref"] = json!(generation_ref);
            payload["auth_data"]["device_authorize_event_id"] = json!(authorize_event_id);
        }
    }
    let mut unsigned = payload.clone();
    unsigned["auth_data"]
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("active-series auth_data is not an object"))?
        .remove("signature");
    let signature = signer
        .sign_raw(&crate::canonical::canonical_json_bytes(&unsigned)?)
        .map_err(|error| anyhow::anyhow!("sign active mls_history series: {error}"))?;
    payload["auth_data"]["signature"] = Value::String(B64.encode(signature));

    let controller = arkret_sdk::Did::new(controller_id.to_owned())?;
    OperationBuilder::new(
        arkret_sdk::principal_control_realm_id(&controller),
        controller_id,
        EventKind::KeyBackupActiveSeries,
    )
    .body(payload)
    .build_sdk_event("inkson")
}

fn principal_bound_active_series_verification_method(
    controller_id: &str,
    signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<String> {
    let device_id = signer
        .device_id()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("active controller device id is unavailable"))?;
    arkret_sdk::DidUrl::new(format!("{controller_id}#{device_id}"))
        .map(|method| method.to_string())
        .map_err(|error| anyhow::anyhow!(error))
}

fn agent_pcr_recovery_matches(
    state: &AgentPcrRecoveryState,
    expected_backup_id: &str,
    expected_frontier: &ManagedFrontierRef,
) -> bool {
    matches!(
        state,
        AgentPcrRecoveryState::Ready {
            backup_id,
            managed_frontier_ref,
            ..
        } if backup_id.as_str() == expected_backup_id
            && managed_frontier_ref == expected_frontier
    )
}

async fn wait_for_agent_pcr_recovery_ready(
    http: &arkret_sdk::http_client::Client,
    agent_id: &str,
    expected_backup_id: &str,
    expected_frontier: &ManagedFrontierRef,
) -> anyhow::Result<()> {
    let mut last_state = None;
    for attempt in 0..PCR_RECOVERY_PROJECTION_WAIT_ATTEMPTS {
        let view = http.agent_get(agent_id).await?;
        let Some(key_state) = view.key_state.as_ref() else {
            anyhow::bail!("Agent details omitted PCR recovery state after setup");
        };
        if agent_pcr_recovery_matches(
            &key_state.pcr_recovery,
            expected_backup_id,
            expected_frontier,
        ) {
            return Ok(());
        }
        last_state = Some(key_state.pcr_recovery.clone());
        if attempt + 1 < PCR_RECOVERY_PROJECTION_WAIT_ATTEMPTS {
            // Agent details are an asynchronously maintained projection. Back
            // off to avoid turning normal projection lag into a request storm.
            let delay_ms = (250_u64 << attempt.min(3)).min(2_000);
            crate::runtime_helpers::sleep_for(Duration::from_millis(delay_ms)).await;
        }
    }
    match last_state {
        Some(AgentPcrRecoveryState::Pending) => anyhow::bail!(
            "Agent recovery backup was accepted, but its recovery projection remained pending"
        ),
        Some(AgentPcrRecoveryState::Stale { .. }) => anyhow::bail!(
            "Agent recovery backup was accepted, but its recovery projection did not catch up to the published Agent frontier"
        ),
        Some(AgentPcrRecoveryState::Ready { .. }) => anyhow::bail!(
            "Agent recovery projection became ready for a different backup or Agent frontier"
        ),
        None => anyhow::bail!("Agent recovery projection was unavailable after setup"),
    }
}

async fn collect_current_managed_pcr_backup_items(
    http: &arkret_sdk::http_client::Client,
    submitter: &crate::event_submit::EventSubmitter,
    state_store: &SyncSignal<LocalStateStore>,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    controller_id: &str,
    device_id: &str,
    current: ManagedPcrBackupItem,
) -> anyhow::Result<Vec<ManagedPcrBackupItem>> {
    let current_binding = current
        .binding
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("current Agent PCR backup item has no managed binding"))?;
    let current_agent_id = current_binding.managed_principal_id.to_string();
    let mut agent_realm_ids = BTreeSet::from([current_binding
        .principal_control_realm_id
        .as_str()
        .to_owned()]);
    let mut items = std::collections::BTreeMap::from([(current_agent_id.clone(), current)]);
    let directory = http.agent_list().await?;
    if directory.has_more {
        anyhow::bail!(
            "Agent directory is paginated; refusing to replace the active recovery series with an incomplete managed-PCR set"
        );
    }
    for agent in directory.agents {
        if agent.agent_id.as_str() == current_agent_id.as_str() {
            continue;
        }
        let view = http.agent_get(agent.agent_id.as_str()).await?;
        let Some(key_state) = view.key_state else {
            if agent.lifecycle
                == arkret_models_collaboration::agent_operations::AgentLifecycleState::Deactivated
            {
                continue;
            }
            return Err(anyhow::anyhow!(
                "Agent {} has no authoritative PCR binding",
                agent.agent_id.as_str()
            ));
        };
        agent_realm_ids.insert(key_state.principal_control_realm_id.as_str().to_owned());
        if agent.lifecycle
            == arkret_models_collaboration::agent_operations::AgentLifecycleState::Deactivated
        {
            continue;
        }
        if key_state.controller_id.as_str() != controller_id {
            anyhow::bail!(
                "Agent {} belongs to a different controller",
                key_state.agent_id.as_str()
            );
        }
        let realm_id = key_state.principal_control_realm_id.as_str();
        let frontier = match submitter.events_frontier_realm_seal_view(realm_id).await {
            Ok(frontier) => frontier,
            // An Agent whose PCR bootstrap never completed has nothing to put
            // in the shared recovery series: the Principal Server reports its
            // recovery projection as `Pending` AND serves no accepted
            // device-signed Seal, so there is no frontier to bind and no
            // recoverable state to lose. Hard-failing here let one interrupted
            // provision block every later Agent for good. Skipping is
            // convergent: when that Agent's own setup finishes it re-collects
            // the whole set and republishes a series that covers it.
            //
            // Both conditions are required. A `Pending` Agent whose frontier
            // fails for any other reason, or a `Ready`/`Stale` Agent that has
            // real recovery state, still fails closed — dropping either from
            // the series would silently narrow recovery coverage.
            Err(error) if managed_pcr_setup_never_completed(&key_state.pcr_recovery, &error) => {
                tracing::warn!(
                    target: "inkson::agents",
                    agent_id = key_state.agent_id.as_str(),
                    "Agent PCR recovery setup never completed; excluding it from this recovery \
                     series until its own setup finishes: {error}"
                );
                continue;
            }
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "Agent {} PCR frontier is unavailable; finish its recovery setup first: {error}",
                    key_state.agent_id.as_str()
                ));
            }
        };
        let snapshot = state_store.read().mls_snapshot_for(realm_id).ok_or_else(|| {
            anyhow::anyhow!(
                "Agent {} has no local PCR MLS state; restore it before rotating the shared recovery series",
                key_state.agent_id.as_str()
            )
        })?;
        let snapshot_secret = crate::mls::runtime::load_device_snapshot_secret(
            secure_store,
            key_state.agent_id.as_str(),
            device_id,
        )
        .map_err(|error| {
            anyhow::anyhow!(
                "load Agent {} PCR snapshot secret: {error}",
                key_state.agent_id.as_str()
            )
        })?;
        let state_bytes = crate::mls::persistence::decrypt_envelope(&snapshot, &snapshot_secret)
            .map_err(|error| {
                anyhow::anyhow!(
                    "open Agent {} PCR MLS state for recovery: {error}",
                    key_state.agent_id.as_str()
                )
            })?;
        let binding = ManagedPrincipalBinding {
            managed_principal_id: key_state.agent_id.clone(),
            controller_id: key_state.controller_id,
            principal_control_realm_id: key_state.principal_control_realm_id,
            authorization_ref: key_state.controller_authorization_ref.to_string(),
            managed_frontier_ref: ManagedFrontierRef {
                frontier_digest: frontier.control_event_set_root,
                seal_ref: frontier.seal_id.to_string(),
                mls_epoch: snapshot.epoch,
            },
        };
        items.insert(
            binding.managed_principal_id.to_string(),
            ManagedPcrBackupItem {
                snapshot,
                state_bytes,
                binding: Some(binding),
            },
        );
    }

    let ordinary_snapshots = state_store
        .read()
        .mls_snapshots()
        .into_values()
        .filter(|snapshot| !agent_realm_ids.contains(snapshot.realm_id.as_str()))
        .collect::<Vec<_>>();
    if !ordinary_snapshots.is_empty() {
        let controller_secret = crate::mls::runtime::load_device_snapshot_secret(
            secure_store,
            controller_id,
            device_id,
        )
        .map_err(|error| anyhow::anyhow!("load controller MLS snapshot secret: {error}"))?;
        for snapshot in ordinary_snapshots {
            let state_bytes =
                crate::mls::persistence::decrypt_envelope(&snapshot, &controller_secret).map_err(
                    |error| {
                        anyhow::anyhow!(
                            "open controller Realm {} MLS state for recovery: {error}",
                            snapshot.realm_id
                        )
                    },
                )?;
            items.insert(
                format!("realm:{}", snapshot.realm_id),
                ManagedPcrBackupItem {
                    snapshot: snapshot.clone(),
                    state_bytes,
                    binding: None,
                },
            );
        }
    }
    Ok(items.into_values().collect())
}

fn has_managed_agent_pcr_create(events: &[arkret_sdk::Event]) -> bool {
    events.iter().any(|event| {
        event.kind.as_str() == arkret_sdk::EventKind::REALM_CREATE
            && event.executed_by.is_some()
            && event
                .payload
                .get("object")
                .and_then(|object| object.get("fields"))
                .and_then(|fields| fields.get("purpose"))
                .and_then(serde_json::Value::as_str)
                == Some("principal_control")
    })
}

async fn submit_managed_agent_pcr_seal(
    http: &arkret_sdk::http_client::Client,
    signer: &crate::event_signer::InksonEventSigner,
    controller_id: &arkret_sdk::Did,
    device_id: &str,
    realm_id: &str,
    events: &[arkret_sdk::Event],
    predecessor: Option<&arkret_sdk::Seal>,
) -> anyhow::Result<arkret_sdk::Seal> {
    let hlc =
        crate::signing_stamp::issue_protocol_hlc(controller_id.as_str(), device_id, realm_id)?;
    let seal = signer
        .sign_managed_agent_pcr_event_seal(controller_id, events, predecessor, hlc)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let expected_digests = seal.delta.clone();
    let outcome = http.events_submit_seal(&seal).await?;
    if outcome.seal_id != seal.id
        || outcome.accepted_event_digests != expected_digests
        || outcome.post_state_root != seal.state_root
    {
        anyhow::bail!("Principal Server returned a mismatched managed Agent PCR Seal outcome");
    }
    Ok(seal)
}

// Invariant assertions: each `expect` message names the check that
// establishes it a few lines earlier. Rewriting them as `?` would add
// error paths no caller can reach.
#[allow(clippy::expect_used)]
/// Close all currently accepted managed Agent PCR Events into a Seal signed by
/// the active controller device. The accepted head returned by frontier can
/// lag the Event log and is the predecessor for the successor authored here.
pub(crate) async fn ensure_managed_agent_pcr_seal_current<
    S: crate::mls::governance_proof::GovernanceProofStateStore,
>(
    submitter: &crate::event_submit::EventSubmitter,
    http: &arkret_sdk::http_client::Client,
    signer: &crate::event_signer::InksonEventSigner,
    controller_id: &arkret_sdk::Did,
    device_id: &str,
    realm_id: &str,
    state_store: S,
) -> anyhow::Result<(arkret_sdk::RealmSealFrontierView, arkret_sdk::Seal)> {
    let current = submitter
        .events_frontier_managed_agent_seal_head(realm_id, controller_id, state_store.clone())
        .await;
    if current
        .as_ref()
        .is_err_and(managed_agent_seal_head_receipt_unavailable)
    {
        return Err(current.expect_err("checked managed PCR signed-head receipt error"));
    }
    let accepted_events = submitter.backfill(realm_id).await?.events;
    let material = arkret_bootstrap::materialize_managed_agent_pcr_control(
        &accepted_events,
        &crate::operation::cell_write_projector,
    )
    .map_err(|error| anyhow::anyhow!("managed Agent PCR materialization failed: {error}"))?;

    let submitted = match current {
        Ok((view, head)) => {
            if head.covered_event_digests == material.covered_event_digests {
                if head.state_root != material.state_root {
                    anyhow::bail!(
                        "accepted managed Agent PCR Seal state differs from accepted Events"
                    );
                }
                return Ok((view, head));
            }
            Some(
                submit_managed_agent_pcr_seal(
                    http,
                    signer,
                    controller_id,
                    device_id,
                    realm_id,
                    &accepted_events,
                    Some(&head),
                )
                .await?,
            )
        }
        Err(error) if managed_agent_initial_seal_required(&error) => Some({
            // Re-publish the exact genesis before the first Seal. New
            // servers return the stored duplicate receipt; servers
            // upgraded from the pre-receipt managed-PCR path use this
            // idempotent retry to attach the first valid proposal receipt
            // and rebuild the durable pending index that the atomic Seal
            // commit consumes.
            let creates = accepted_events
                .iter()
                .filter(|event| {
                    event.kind.as_str() == arkret_sdk::EventKind::REALM_CREATE
                        && event.realm_id.as_str() == realm_id
                })
                .collect::<Vec<_>>();
            let [create] = creates.as_slice() else {
                anyhow::bail!(
                    "managed Agent PCR initial Seal requires exactly one accepted create Event"
                );
            };
            let submission =
                crate::authorization_lease::standard_initial_submission(http, create).await?;
            http.events_submit(&submission).await?;
            submit_managed_agent_pcr_seal(
                http,
                signer,
                controller_id,
                device_id,
                realm_id,
                &accepted_events,
                None,
            )
            .await?
        }),
        Err(error) => return Err(error),
    };

    let expected = submitted.expect("managed PCR Seal submission branch always returns a Seal");
    let (view, head) = submitter
        .events_frontier_managed_agent_seal_head(realm_id, controller_id, state_store)
        .await?;
    if head.id != expected.id
        || head.state_root != expected.state_root
        || head.covered_event_digests != material.covered_event_digests
    {
        anyhow::bail!("accepted managed Agent PCR Seal differs from the submitted successor");
    }
    Ok((view, head))
}

pub(crate) fn managed_agent_seal_head_receipt_unavailable(error: &anyhow::Error) -> bool {
    error
        .to_string()
        .contains("events/frontier omitted the accepted managed Agent PCR Seal head")
}

/// Publish the controller-authored successor Seal required to turn durable
/// managed Agent-PCR Events into accepted authorization state.
pub(crate) async fn seal_managed_agent_pcr_current(
    api: &crate::transport::TransportClient,
    state_store: SyncSignal<LocalStateStore>,
    realm_id: &arkret_sdk::RealmId,
) -> anyhow::Result<arkret_sdk::Seal> {
    let controller_id = state_store
        .read()
        .active_account_did()
        .filter(|did| !did.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("active controller DID is unavailable"))?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active controller signer is unavailable"))?;
    let signer_account_scope = crate::secure_key_store::active_device_seed_scope();
    let device_id = controller_signer_device_id(
        &controller_id,
        signer.as_ref(),
        signer_account_scope.as_deref(),
    )?;
    let controller_did = arkret_sdk::Did::new(controller_id)?;
    let submitter = api.event_submitter()?;
    let http = api.sdk_http_client()?;
    let (_, seal) = ensure_managed_agent_pcr_seal_current(
        &submitter,
        &http,
        signer.as_ref(),
        &controller_did,
        &device_id,
        realm_id.as_str(),
        state_store,
    )
    .await?;
    Ok(seal)
}

/// Complete the client-owned half of `agent_provision`: create the Agent PCR,
/// generate its epoch-0 MLS state locally, publish a controller-owned managed
/// recovery envelope, and select that envelope's series from the controller
/// PCR before returning pairing material to the UI.
pub(crate) async fn bootstrap_provisioned_agent(
    api: &crate::transport::TransportClient,
    mut state_store: SyncSignal<LocalStateStore>,
    agent_id: &arkret_sdk::Did,
    realm_id: &arkret_sdk::RealmId,
    controller_authorization_ref: &str,
    previous_seal_id: Option<&str>,
) -> anyhow::Result<()> {
    let controller_id = state_store
        .read()
        .active_account_did()
        .filter(|did| !did.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("active controller DID is unavailable"))?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active controller signer is unavailable"))?;
    let signer_account_scope = crate::secure_key_store::active_device_seed_scope();
    let device_id = controller_signer_device_id(
        &controller_id,
        signer.as_ref(),
        signer_account_scope.as_deref(),
    )?;
    let controller_did = arkret_sdk::Did::new(controller_id.clone())?;
    let agent_id = agent_id.as_str();
    let realm_id = realm_id.as_str();
    let submitter = api.event_submitter()?;
    let http = api.sdk_http_client()?;
    let trust_anchor =
        current_controller_backup_trust_anchor(&http, &controller_id, &device_id).await?;

    if previous_seal_id.is_none()
        && http
            .agent_get(agent_id)
            .await?
            .key_state
            .as_ref()
            .is_some_and(|state| state.pcr_recovery.is_ready())
    {
        return Ok(());
    }

    let mut accepted_events = submitter.backfill(realm_id).await?.events;
    if !has_managed_agent_pcr_create(&accepted_events) {
        let controller_realm_id =
            arkret_models_identity::did_document::principal_control_realm_id(&controller_did);
        let provision_event_id = http
            .events_query_all_pages(controller_realm_id.as_str())
            .await?
            .events
            .into_iter()
            .find_map(|event| {
                (event.kind == arkret_sdk::EventKind::AGENT_PROVISION)
                    .then(|| {
                        arkret_sdk::AgentProvisionPayload::try_from(&event)
                            .ok()
                            .filter(|payload| payload.agent_id.as_str() == agent_id)
                            .map(|_| event.event_id)
                    })
                    .flatten()
            })
            .ok_or_else(|| {
                anyhow::anyhow!("accepted Agent provision Event is missing from the controller PCR")
            })?;
        let describe = submitter.events_describe().await?;
        let bootstrap = crate::event_builders::build_managed_agent_pcr_bootstrap_events(
            agent_id,
            &controller_id,
            controller_authorization_ref,
            describe.trust_domain.as_str(),
            provision_event_id,
        )?;
        submitter
            .submit_sdk_events_batch(realm_id, bootstrap, None)
            .await?;
        accepted_events = submitter.backfill(realm_id).await?.events;
    }
    if !has_managed_agent_pcr_create(&accepted_events) {
        anyhow::bail!("Principal Server did not expose the accepted managed Agent PCR genesis");
    }

    let (initial_frontier, _) = ensure_managed_agent_pcr_seal_current(
        &submitter,
        &http,
        signer.as_ref(),
        &controller_did,
        &device_id,
        realm_id,
        state_store,
    )
    .await?;
    state_store.write().set_realm_seal_view(
        realm_id.to_owned(),
        crate::state::LocalSealView {
            frontier: vec![initial_frontier.seal_id.to_string()],
            state_root: Some(initial_frontier.state_root.to_string()),
            ..Default::default()
        },
    );

    let group_id = arkret_sdk::base64url_encode(realm_id.as_bytes());
    let proof_request = crate::mls::governance_proof::proof_request(
        &state_store.read(),
        realm_id,
        None,
        group_id,
        0,
        0,
    )
    .map_err(anyhow::Error::msg)?;
    let leaves =
        crate::mls::governance_proof::singleton_security_frontier_leaf(agent_id, &device_id)
            .map_err(anyhow::Error::msg)?;
    crate::mls::governance_proof::fetch_verify_and_cache_proof_bundle(
        api,
        state_store,
        &proof_request,
        &leaves,
    )
    .await
    .map_err(anyhow::Error::msg)?;

    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let existing_genesis = submitter.find_mls_genesis_event_id(realm_id).await?;
    let frontier = if let Some(event_id) = existing_genesis {
        state_store
            .write()
            .mark_mls_genesis_emitted_with_event(realm_id.to_owned(), &event_id);
        if state_store.read().mls_snapshot_for(realm_id).is_none() {
            anyhow::bail!(
                "Agent PCR MLS genesis exists, but this controller device has no local private group state"
            );
        }
        ensure_managed_agent_pcr_seal_current(
            &submitter,
            &http,
            signer.as_ref(),
            &controller_did,
            &device_id,
            realm_id,
            state_store,
        )
        .await?
        .0
    } else {
        let summary = {
            let mut store = state_store.write();
            match crate::mls::runtime::ensure_creator_mls_snapshot(
                &mut store,
                secure_store.as_ref(),
                realm_id,
                agent_id,
                &device_id,
            )
            .map_err(|error| anyhow::anyhow!(error.user_message()))?
            {
                Some(summary) => summary,
                None => crate::mls::runtime::initial_mls_snapshot_summary_from_existing(
                    &store,
                    secure_store.as_ref(),
                    realm_id,
                    agent_id,
                    &device_id,
                )
                .map_err(|error| anyhow::anyhow!(error.user_message()))?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Agent PCR has no recoverable epoch-0 MLS state for genesis retry"
                    )
                })?,
            }
        };
        let mut genesis = {
            let mut store = state_store.write();
            crate::mls::group_events::build_creator_mls_genesis_event(
                &mut store,
                realm_id,
                agent_id,
                &device_id,
                Some(&summary),
            )
            .map_err(anyhow::Error::msg)?
        }
        .ok_or_else(|| anyhow::anyhow!("Agent PCR MLS genesis was not built"))?;
        genesis.executed_by = Some(arkret_sdk::Did::new(controller_id.clone())?);
        genesis.authorization_ref = Some(
            arkret_sdk::AuthorizationRef::new(controller_authorization_ref.to_owned())
                .map_err(anyhow::Error::msg)?,
        );
        crate::mls::runtime::upload_mls_genesis_public_material(api, &summary)
            .await
            .map_err(|error| anyhow::anyhow!(error.user_message()))?;
        match submitter.submit_sdk_event(&genesis).await {
            Ok(_) => state_store
                .write()
                .mark_mls_genesis_emitted_with_event(realm_id.to_owned(), &genesis.event_id),
            Err(error) if error.to_string().contains("mls_genesis_already_exists") => {
                let event_id = submitter
                    .find_mls_genesis_event_id(realm_id)
                    .await?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "Agent PCR reports duplicate MLS genesis but exposes no accepted genesis"
                        )
                    })?;
                state_store
                    .write()
                    .mark_mls_genesis_emitted_with_event(realm_id.to_owned(), &event_id);
            }
            Err(error) => return Err(error),
        }
        let (frontier, _) = ensure_managed_agent_pcr_seal_current(
            &submitter,
            &http,
            signer.as_ref(),
            &controller_did,
            &device_id,
            realm_id,
            state_store,
        )
        .await?;
        frontier
    };
    state_store.write().set_realm_seal_view(
        realm_id.to_owned(),
        crate::state::LocalSealView {
            frontier: vec![frontier.seal_id.to_string()],
            state_root: Some(frontier.state_root.to_string()),
            ..Default::default()
        },
    );
    let snapshot = state_store
        .read()
        .mls_snapshot_for(realm_id)
        .ok_or_else(|| anyhow::anyhow!("Agent PCR MLS snapshot was not persisted"))?;
    let active_policy = crate::recovery_strand::fetch_active_recovery_policy(api)
        .await?
        .ok_or_else(|| anyhow::anyhow!("active controller recovery policy is unavailable"))?;
    let binding = ManagedPrincipalBinding {
        managed_principal_id: arkret_sdk::Did::new(agent_id.to_owned())?,
        controller_id: arkret_sdk::Did::new(controller_id.clone())?,
        principal_control_realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())?,
        authorization_ref: controller_authorization_ref.to_owned(),
        managed_frontier_ref: ManagedFrontierRef {
            frontier_digest: frontier.control_event_set_root.clone(),
            seal_ref: frontier.seal_id.to_string(),
            mls_epoch: snapshot.epoch,
        },
    };
    let envelope_frontier = binding.managed_frontier_ref.clone();
    let list_payload =
        crate::mls::account_recovery::fetch_mls_restore_payload(api, &controller_id).await?;
    let highest_seen = state_store
        .read()
        .key_backup_active_series_highest_seen(&controller_id, "mls_history");
    let current =
        current_mls_history_active_series(&submitter, &controller_id, highest_seen).await?;
    if let Some(current) = current.as_ref() {
        let persist = {
            let mut state = state_store.write();
            state.observe_key_backup_active_series_version(
                &controller_id,
                "mls_history",
                current.pointer_version,
            )?;
            state.begin_durable_flush()?
        };
        persist.wait().await?;
    }
    let recovery_plan = resolve_mls_history_series_target(
        api,
        &list_payload,
        current,
        &controller_id,
        &device_id,
        (active_policy.policy_id.as_str(), active_policy.version),
        &binding,
    )
    .await?;

    let series_target = match recovery_plan {
        MlsHistoryRecoveryPlan::Reuse {
            backup_id,
            series_id,
            publish_pointer,
        } => {
            if let Some((pointer_version, previous_series_ids)) = publish_pointer {
                let controller_realm_id = arkret_sdk::principal_control_realm_id(&controller_did);
                let controller_frontier = submitter
                    .events_frontier_realm_seal_view(controller_realm_id.as_str())
                    .await?;
                let active_series = build_active_mls_history_series_event(
                    &controller_id,
                    &series_id,
                    pointer_version,
                    &previous_series_ids,
                    &controller_frontier,
                    &trust_anchor,
                )?;
                submitter.submit_sdk_event(&active_series).await?;
                let persist = {
                    let mut state = state_store.write();
                    state.observe_key_backup_active_series_version(
                        &controller_id,
                        "mls_history",
                        pointer_version,
                    )?;
                    state.begin_durable_flush()?
                };
                persist.wait().await?;
            }
            return wait_for_agent_pcr_recovery_ready(
                &http,
                agent_id,
                &backup_id,
                &envelope_frontier,
            )
            .await;
        }
        MlsHistoryRecoveryPlan::Write(series_target) => series_target,
    };
    let snapshot_secret = crate::mls::runtime::load_device_snapshot_secret(
        secure_store.as_ref(),
        agent_id,
        &device_id,
    )
    .map_err(|error| anyhow::anyhow!("load Agent PCR snapshot secret: {error}"))?;
    let state_bytes = crate::mls::persistence::decrypt_envelope(&snapshot, &snapshot_secret)
        .map_err(|error| anyhow::anyhow!("open Agent PCR MLS snapshot for recovery: {error}"))?;
    let recovery_public_key = crate::views::recovery::local_recovery_public_key_result(
        &state_store.read(),
        &controller_id,
    )?;
    let recovery_key_ref = current_controller_backup_hpke_key_ref(
        &active_policy,
        &controller_id,
        &recovery_public_key,
        crate::clock::now_utc(),
    )?;
    let managed_items = collect_current_managed_pcr_backup_items(
        &http,
        &submitter,
        &state_store,
        secure_store.as_ref(),
        &controller_id,
        &device_id,
        ManagedPcrBackupItem {
            snapshot,
            state_bytes,
            binding: Some(binding),
        },
    )
    .await?;
    let backup_id = format!("ak:backup:{}", uuid_v7());
    let backup = build_managed_pcr_backup_body(
        &managed_items,
        &envelope_frontier,
        &controller_id,
        &device_id,
        &recovery_public_key,
        &recovery_key_ref,
        (active_policy.policy_id.as_str(), active_policy.version),
        &backup_id,
        &series_target.series_id,
        series_target.series_seq,
        series_target.previous_tail.as_ref(),
        &trust_anchor,
        Some(&signer),
    )?;
    api.put_key_backup(&backup_id, backup, Some(&signer))
        .await?;

    if let Some((pointer_version, previous_series_ids)) = series_target.publish_pointer {
        let controller_realm_id = arkret_sdk::principal_control_realm_id(&controller_did);
        let controller_frontier = submitter
            .events_frontier_realm_seal_view(controller_realm_id.as_str())
            .await?;
        let active_series = build_active_mls_history_series_event(
            &controller_id,
            &series_target.series_id,
            pointer_version,
            &previous_series_ids,
            &controller_frontier,
            &trust_anchor,
        )?;
        submitter.submit_sdk_event(&active_series).await?;
        let persist = {
            let mut state = state_store.write();
            state.observe_key_backup_active_series_version(
                &controller_id,
                "mls_history",
                pointer_version,
            )?;
            state.begin_durable_flush()?
        };
        persist.wait().await?;
    }
    // Backup storage and the controller active-series Event are accepted
    // before the Agent directory projection necessarily observes both. Wait
    // for the exact backup/frontier pair published above instead of treating
    // normal projection lag as a failed setup (or accepting an older ready
    // projection).
    wait_for_agent_pcr_recovery_ready(&http, agent_id, &backup_id, &envelope_frontier).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DEVICE_ID: &str = "ak:device:01964137-0000-7000-8000-000000000001";

    fn api_error(status: u16, code: &str) -> anyhow::Error {
        anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status,
            error: Box::new(arkret_wire::ErrorEnvelope::new(code, "test error")),
        })
    }

    #[test]
    fn managed_agent_initial_seal_accepts_missing_frontier_states() {
        assert!(managed_agent_initial_seal_required(&api_error(
            404,
            "not_found"
        )));
        assert!(managed_agent_initial_seal_required(&api_error(
            503,
            "frontier_unavailable"
        )));
    }

    #[test]
    fn managed_agent_initial_seal_does_not_hide_other_api_failures() {
        assert!(!managed_agent_initial_seal_required(&api_error(
            503,
            "service_unavailable"
        )));
        assert!(!managed_agent_initial_seal_required(&api_error(
            403,
            "capability_denied"
        )));
    }

    fn ready_recovery() -> AgentPcrRecoveryState {
        AgentPcrRecoveryState::Ready {
            backup_id: arkret_sdk::BackupId::new(
                "ak:backup:01964137-0000-7000-8000-000000000010".to_owned(),
            )
            .unwrap(),
            series_id: arkret_sdk::BackupSeriesId::new(
                "ak:backup_series:01964137-0000-7000-8000-000000000011".to_owned(),
            )
            .unwrap(),
            series_seq: 1,
            managed_frontier_ref: ManagedFrontierRef {
                frontier_digest: arkret_sdk::Hash::new(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_owned(),
                )
                .unwrap(),
                seal_ref: "ak:seal:01964137-0000-7000-8000-000000000012".to_owned(),
                mls_epoch: 0,
            },
        }
    }

    #[test]
    fn pending_agent_without_an_accepted_seal_is_excluded_from_the_series() {
        // One interrupted provision must not block every later Agent: the
        // Principal Server reports both "no series published" and "no accepted
        // device-signed Seal", so there is nothing to lose by skipping it.
        assert!(managed_pcr_setup_never_completed(
            &AgentPcrRecoveryState::Pending,
            &api_error(503, "frontier_unavailable")
        ));
        assert!(managed_pcr_setup_never_completed(
            &AgentPcrRecoveryState::Pending,
            &api_error(404, "not_found")
        ));
    }

    #[test]
    fn an_agent_with_recovery_state_still_fails_the_series_closed() {
        // Ready/Stale Agents own real recovery material — dropping them would
        // silently narrow coverage, so the frontier error must propagate.
        assert!(!managed_pcr_setup_never_completed(
            &ready_recovery(),
            &api_error(503, "frontier_unavailable")
        ));
        // A Pending Agent whose frontier failed for an unrelated reason is not
        // evidence that its setup never ran.
        assert!(!managed_pcr_setup_never_completed(
            &AgentPcrRecoveryState::Pending,
            &api_error(503, "service_unavailable")
        ));
        assert!(!managed_pcr_setup_never_completed(
            &AgentPcrRecoveryState::Pending,
            &api_error(403, "capability_denied")
        ));
    }

    #[test]
    fn controller_signer_accepts_account_scoped_device_did_key() {
        let controller_id = "did:web:alice.example";
        let signer = crate::event_signer::build_ed25519_device_signer(
            [31_u8; 32],
            "did:key:z6MkhDeviceSigningKey",
            TEST_DEVICE_ID,
        );

        assert_eq!(
            controller_signer_device_id(controller_id, &signer, Some(controller_id)).unwrap(),
            TEST_DEVICE_ID
        );
    }

    #[test]
    fn active_series_uses_the_controller_principal_bound_device_method() {
        let controller_id = "did:web:alice.example";
        let signer = crate::event_signer::build_ed25519_device_signer(
            [35_u8; 32],
            "did:key:z6MkhLocalDeviceSigningKey",
            TEST_DEVICE_ID,
        );

        assert_eq!(
            principal_bound_active_series_verification_method(controller_id, &signer).unwrap(),
            format!("{controller_id}#{TEST_DEVICE_ID}")
        );
        assert_ne!(
            principal_bound_active_series_verification_method(controller_id, &signer).unwrap(),
            signer.verification_method()
        );
    }

    #[test]
    fn managed_backup_selects_exact_current_policy_hpke_ref_by_key_bytes() {
        let controller = "did:web:alice.example";
        let recipient = format!("{controller}#backup-hpke-7");
        let (_private_key, public_key) = crate::hpke_backup::derive_recovery_keypair_from_entropy(
            &[29_u8; crate::recovery_crypto::RECOVERY_KEY_BYTES],
        )
        .unwrap();
        let public_multikey = crate::identity::did_key::encode_x25519_multibase(&public_key);
        let issued_at = "2026-07-17T00:00:00.000Z";
        let expires_at = "2036-07-17T00:00:00.000Z";
        let policy_id = "ak:policy:01964137-0000-7000-8000-000000000071";
        let policy: crate::recovery_strand::ActiveRecoveryPolicy = serde_json::from_value(json!({
            "policy_id": policy_id,
            "principal_id": controller,
            "version": 1,
            "acceptance_basis": format!("ak:seal:sha256:{}", "a".repeat(64)),
            "trust_domain": "ak:trust_domain:example.org",
            "allowed_proof_kinds": ["principal_signing"],
            "issued_at": issued_at,
            "accepted_at": issued_at,
            "policy": {
                "schema": "ak.schema.recovery_policy.v1",
                "policy_id": policy_id,
                "principal_id": controller,
                "version": 1,
                "supersedes": null,
                "trust_domain": "ak:trust_domain:example.org",
                "allowed_proof_kinds": ["principal_signing"],
                "publication_authorization_rules": [{
                    "rule_id": "principal_signing",
                    "proof_kind": "principal_signing",
                    "issuer_role": "identity_recovery",
                    "allowed_actions": ["ak.device.reanchor"],
                    "issuers": [{
                        "verification_method": format!("{controller}#device")
                    }],
                    "threshold": 1
                }],
                "recovery_key_agreements": [{
                    "key_agreement_ref": recipient,
                    "key_agreement_algorithm": "X25519",
                    "public_key_multibase": public_multikey,
                    "hpke_suites": ["ak.hpke_x25519_aead_chacha20poly1305.v1"],
                    "use": "backup_hpke",
                    "not_before": issued_at,
                    "expires_at": expires_at
                }],
                "issued_at": issued_at,
                "auth_data": {
                    "verification_method": format!("{controller}#device"),
                    "signature_algorithm": "Ed25519",
                    "signature": "fixture",
                    "signed_fields": [
                        "schema", "policy_id", "principal_id", "version", "supersedes",
                        "trust_domain", "allowed_proof_kinds",
                        "publication_authorization_rules", "recovery_key_agreements", "issued_at"
                    ]
                }
            }
        }))
        .unwrap();
        let evaluated_at = chrono::DateTime::parse_from_rfc3339("2026-07-18T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        assert_eq!(
            current_controller_backup_hpke_key_ref(&policy, controller, &public_key, evaluated_at,)
                .unwrap(),
            recipient
        );
        let mut other_key = public_key.clone();
        other_key[0] ^= 0xff;
        assert!(
            current_controller_backup_hpke_key_ref(&policy, controller, &other_key, evaluated_at,)
                .is_err()
        );
    }

    #[test]
    fn controller_signer_rejects_device_key_from_another_account_scope() {
        let signer = crate::event_signer::build_ed25519_device_signer(
            [32_u8; 32],
            "did:key:z6MkhOtherDeviceSigningKey",
            TEST_DEVICE_ID,
        );

        let error = controller_signer_device_id(
            "did:web:alice.example",
            &signer,
            Some("did:web:bob.example"),
        )
        .unwrap_err();

        assert!(error.to_string().contains("is not bound to controller"));
    }

    #[test]
    fn controller_signer_rejects_controller_did_when_account_scope_differs() {
        let controller_id = "did:web:alice.example";
        let signer = crate::event_signer::build_ed25519_device_signer(
            [34_u8; 32],
            controller_id,
            TEST_DEVICE_ID,
        );

        let error =
            controller_signer_device_id(controller_id, &signer, Some("did:web:bob.example"))
                .unwrap_err();

        assert!(error.to_string().contains("is not bound to controller"));
    }

    #[test]
    fn controller_signer_accepts_controller_identified_external_signer() {
        let controller_id = "did:web:alice.example";
        let signer = crate::event_signer::build_ed25519_device_signer(
            [33_u8; 32],
            controller_id,
            TEST_DEVICE_ID,
        );

        assert_eq!(
            controller_signer_device_id(controller_id, &signer, None).unwrap(),
            TEST_DEVICE_ID
        );
    }

    #[test]
    fn active_series_successor_retains_all_prior_series_ids() {
        let current = MlsHistoryActiveSeries {
            series_id: "ak:backup_series:01964137-0000-7000-8000-000000000003".to_owned(),
            pointer_version: 4,
            previous_series_ids: vec![
                "ak:backup_series:01964137-0000-7000-8000-000000000001".to_owned(),
                "ak:backup_series:01964137-0000-7000-8000-000000000002".to_owned(),
            ],
        };
        let (version, previous) =
            next_mls_history_pointer(Some(&current), std::iter::empty()).unwrap();
        assert_eq!(version, 5);
        assert_eq!(previous.len(), 3);
        assert!(previous.iter().any(|id| id.ends_with("000000000003")));
    }

    #[test]
    fn recovery_ready_must_match_the_just_published_backup_and_frontier() {
        let frontier = ManagedFrontierRef {
            frontier_digest: arkret_sdk::Hash::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            seal_ref: "ak:seal:01964137-0000-7000-8000-000000000001".to_owned(),
            mls_epoch: 0,
        };
        let ready = AgentPcrRecoveryState::Ready {
            backup_id: arkret_sdk::BackupId::new(
                "ak:backup:01964137-0000-7000-8000-000000000002".to_owned(),
            )
            .unwrap(),
            series_id: arkret_sdk::BackupSeriesId::new(
                "ak:backup_series:01964137-0000-7000-8000-000000000003".to_owned(),
            )
            .unwrap(),
            series_seq: 0,
            managed_frontier_ref: frontier.clone(),
        };

        assert!(agent_pcr_recovery_matches(
            &ready,
            "ak:backup:01964137-0000-7000-8000-000000000002",
            &frontier,
        ));
        assert!(!agent_pcr_recovery_matches(
            &ready,
            "ak:backup:01964137-0000-7000-8000-000000000004",
            &frontier,
        ));
        let mut newer_frontier = frontier.clone();
        newer_frontier.mls_epoch = 1;
        assert!(!agent_pcr_recovery_matches(
            &ready,
            "ak:backup:01964137-0000-7000-8000-000000000002",
            &newer_frontier,
        ));
    }

    #[test]
    fn managed_pcr_backup_round_trips_bound_plaintext_keybag() {
        let snapshot = crate::mls::persistence::encrypt_state(
            "ak:realm:01964137-0000-8000-8000-000000000099",
            "YWdlbnQtcGNy",
            0,
            b"real MLS state record bytes",
            "device snapshot secret",
            b"0123456789abcdef",
        );
        let binding = ManagedPrincipalBinding {
            managed_principal_id: arkret_sdk::Did::new("did:web:agent.example").unwrap(),
            controller_id: arkret_sdk::Did::new("did:web:alice.example").unwrap(),
            principal_control_realm_id: arkret_sdk::RealmId::new(snapshot.realm_id.clone())
                .unwrap(),
            authorization_ref: "did:web:agent.example#managed-controller".to_owned(),
            managed_frontier_ref: ManagedFrontierRef {
                frontier_digest: arkret_sdk::Hash::new(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
                seal_ref: "ak:seal:01964137-0000-7000-8000-000000000098".to_owned(),
                mls_epoch: 0,
            },
        };
        let second_snapshot = crate::mls::persistence::encrypt_state(
            "ak:realm:01964137-0000-8000-8000-000000000088",
            "YWdlbnQtcGNyLTI",
            1,
            b"second real MLS state record",
            "second device snapshot secret",
            b"fedcba9876543210",
        );
        let second_binding = ManagedPrincipalBinding {
            managed_principal_id: arkret_sdk::Did::new("did:web:agent-two.example").unwrap(),
            controller_id: arkret_sdk::Did::new("did:web:alice.example").unwrap(),
            principal_control_realm_id: arkret_sdk::RealmId::new(second_snapshot.realm_id.clone())
                .unwrap(),
            authorization_ref: "did:web:agent-two.example#managed-controller".to_owned(),
            managed_frontier_ref: ManagedFrontierRef {
                frontier_digest: arkret_sdk::Hash::new(
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )
                .unwrap(),
                seal_ref: "ak:seal:01964137-0000-7000-8000-000000000087".to_owned(),
                mls_epoch: 1,
            },
        };
        let (private_key, public_key) = crate::hpke_backup::derive_recovery_keypair_from_entropy(
            &[7_u8; crate::recovery_crypto::RECOVERY_KEY_BYTES],
        )
        .unwrap();
        let backup_id = "ak:backup:01964137-0000-7000-8000-000000000011";
        let series_id = "ak:backup_series:01964137-0000-7000-8000-000000000012";
        let envelope_frontier = binding.managed_frontier_ref.clone();
        let body = build_managed_pcr_backup_body(
            &[
                ManagedPcrBackupItem {
                    snapshot: snapshot.clone(),
                    state_bytes: b"real MLS state record bytes".to_vec(),
                    binding: Some(binding.clone()),
                },
                ManagedPcrBackupItem {
                    snapshot: second_snapshot.clone(),
                    state_bytes: b"second real MLS state record".to_vec(),
                    binding: Some(second_binding.clone()),
                },
            ],
            &envelope_frontier,
            "did:web:alice.example",
            "ak:device:01964137-0000-7000-8000-000000000001",
            &public_key,
            "did:web:alice.example#backup-hpke-0",
            ("ak:policy:01964137-0000-7000-8000-000000000013", 1),
            backup_id,
            series_id,
            0,
            None,
            &ControllerBackupTrustAnchor::SskGeneration(1),
            None,
        )
        .unwrap();

        crate::key_backup::validate_key_backup_put_request(backup_id, &body).unwrap();
        let opened =
            crate::key_backup::open_recovery_public_key_backup_body(&private_key, &body).unwrap();
        let plaintext: Value = serde_json::from_slice(&opened).unwrap();
        assert_eq!(plaintext["series_id"], series_id);
        assert_eq!(plaintext["items"].as_array().unwrap().len(), 2);
        assert_eq!(
            plaintext["items"][0]["managed_principal_binding"],
            json!(binding)
        );
        assert_eq!(
            plaintext["items"][1]["managed_principal_binding"],
            json!(second_binding)
        );
        assert_eq!(
            B64.decode(
                plaintext["items"][0]["secret_b64u"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
            )
            .unwrap(),
            b"real MLS state record bytes"
        );
        crate::key_backup::validate_key_backup_plaintext_binding(&body, &plaintext).unwrap();

        let successor_id = "ak:backup:01964137-0000-7000-8000-000000000021";
        let successor = build_managed_pcr_backup_body(
            &[
                ManagedPcrBackupItem {
                    snapshot,
                    state_bytes: b"real MLS state record bytes".to_vec(),
                    binding: Some(binding),
                },
                ManagedPcrBackupItem {
                    snapshot: second_snapshot,
                    state_bytes: b"second real MLS state record".to_vec(),
                    binding: Some(second_binding),
                },
            ],
            &envelope_frontier,
            "did:web:alice.example",
            "ak:device:01964137-0000-7000-8000-000000000001",
            &public_key,
            "did:web:alice.example#backup-hpke-0",
            ("ak:policy:01964137-0000-7000-8000-000000000013", 1),
            successor_id,
            series_id,
            1,
            Some(&body),
            &ControllerBackupTrustAnchor::SskGeneration(1),
            None,
        )
        .unwrap();
        assert_eq!(successor["series_seq"], 1);
        assert_eq!(successor["supersedes"], backup_id);
        crate::key_backup::validate_key_backup_put_request(successor_id, &successor).unwrap();
        let opened =
            crate::key_backup::open_recovery_public_key_backup_body(&private_key, &successor)
                .unwrap();
        let plaintext: Value = serde_json::from_slice(&opened).unwrap();
        assert_eq!(plaintext["series_seq"], 1);
        crate::key_backup::validate_key_backup_plaintext_binding(&successor, &plaintext).unwrap();
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn recovery_key_restores_managed_and_controller_states_from_shared_tail() {
        use arkret_sdk::{ArkretMlsIdentity, DeviceId};

        let controller_id = "did:web:alice.example";
        let agent_id = "did:web:agent.example";
        let device_id = "ak:device:01964137-0000-7000-8000-000000000001";
        let controller_realm = "ak:realm:01964137-0000-8000-8000-000000000081";
        let agent_realm = "ak:realm:01964137-0000-8000-8000-000000000091";
        let controller_identity = ArkretMlsIdentity::new_basic(
            arkret_sdk::Did::new(controller_id.to_owned()).unwrap(),
            DeviceId::new(device_id.to_owned()).unwrap(),
        )
        .unwrap();
        let controller_record = controller_identity
            .create_group(b"controller-realm")
            .unwrap()
            .export_state_record()
            .unwrap();
        let controller_bytes = serde_json::to_vec(&controller_record).unwrap();
        let agent_identity = ArkretMlsIdentity::new_basic(
            arkret_sdk::Did::new(agent_id.to_owned()).unwrap(),
            DeviceId::new(device_id.to_owned()).unwrap(),
        )
        .unwrap();
        let agent_record = agent_identity
            .create_group(b"agent-pcr")
            .unwrap()
            .export_state_record()
            .unwrap();
        let agent_bytes = serde_json::to_vec(&agent_record).unwrap();
        let controller_snapshot = crate::mls::persistence::encrypt_state(
            controller_realm,
            &controller_record.group_id,
            controller_record.epoch,
            &controller_bytes,
            "source controller secret",
            b"controller-salt",
        );
        let agent_snapshot = crate::mls::persistence::encrypt_state(
            agent_realm,
            &agent_record.group_id,
            agent_record.epoch,
            &agent_bytes,
            "source agent secret",
            b"agent-state-salt",
        );
        let binding = ManagedPrincipalBinding {
            managed_principal_id: arkret_sdk::Did::new(agent_id.to_owned()).unwrap(),
            controller_id: arkret_sdk::Did::new(controller_id.to_owned()).unwrap(),
            principal_control_realm_id: arkret_sdk::RealmId::new(agent_realm.to_owned()).unwrap(),
            authorization_ref: format!("{agent_id}#managed-controller"),
            managed_frontier_ref: ManagedFrontierRef {
                frontier_digest: arkret_sdk::Hash::new(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
                seal_ref: "ak:seal:01964137-0000-7000-8000-000000000092".to_owned(),
                mls_epoch: agent_record.epoch,
            },
        };
        let (recovery_private_key, recovery_public_key) =
            crate::hpke_backup::derive_recovery_keypair_from_entropy(
                &[11_u8; crate::recovery_crypto::RECOVERY_KEY_BYTES],
            )
            .unwrap();
        let history_backup_id = "ak:backup:01964137-0000-7000-8000-000000000093";
        let history_series_id = "ak:backup_series:01964137-0000-7000-8000-000000000094";
        let history = build_managed_pcr_backup_body(
            &[
                ManagedPcrBackupItem {
                    snapshot: agent_snapshot,
                    state_bytes: agent_bytes.clone(),
                    binding: Some(binding.clone()),
                },
                ManagedPcrBackupItem {
                    snapshot: controller_snapshot,
                    state_bytes: controller_bytes.clone(),
                    binding: None,
                },
            ],
            &binding.managed_frontier_ref,
            controller_id,
            device_id,
            &recovery_public_key,
            "did:web:alice.example#backup-hpke-0",
            ("ak:recovery_policy:01964137-0000-7000-8000-000000000095", 3),
            history_backup_id,
            history_series_id,
            0,
            None,
            &ControllerBackupTrustAnchor::SskGeneration(1),
            None,
        )
        .unwrap();
        let account =
            crate::mls::account_recovery::build_mls_account_secret_recovery_public_key_backup(
                "ak:backup:01964137-0000-7000-8000-000000000096",
                controller_id,
                device_id,
                &recovery_public_key,
                "did:web:alice.example#recovery",
                "restored controller account secret",
                crate::mls::runtime::ACCOUNT_MLS_SECRET_CURRENT_VERSION,
                ("ak:recovery_policy:01964137-0000-7000-8000-000000000095", 3),
                None,
            )
            .unwrap();
        let account_series_id = account["series_id"].as_str().unwrap();
        let payload = json!({
            "active_series": [
                {
                    "schema": SchemaId::KEY_BACKUP_ACTIVE_SERIES_V1,
                    "actor_id": controller_id,
                    "backup_kind": "secret_storage",
                    "active_series_id": account_series_id,
                    "series_pointer_version": 1
                },
                {
                    "schema": SchemaId::KEY_BACKUP_ACTIVE_SERIES_V1,
                    "actor_id": controller_id,
                    "backup_kind": "mls_history",
                    "active_series_id": history_series_id,
                    "series_pointer_version": 1
                }
            ],
            "backups": [account, history]
        });
        let secure_store = crate::secure_key_store::MemorySecureKeyStore::new();
        let mut state = crate::state::isolated_store_for_tests("managed-pcr-recovery-keybag");
        let report =
            crate::mls::account_recovery::restore_mls_history_with_recovery_key_from_payload(
                &payload,
                &mut state,
                &secure_store,
                controller_id,
                device_id,
                &recovery_private_key,
                ("ak:recovery_policy:01964137-0000-7000-8000-000000000095", 3),
            )
            .unwrap();

        assert_eq!(report.restored, 2);
        assert_eq!(report.failed, 0);
        let restored_agent = state.mls_snapshot_for(agent_realm).unwrap();
        let agent_secret =
            crate::mls::runtime::load_device_snapshot_secret(&secure_store, agent_id, device_id)
                .unwrap();
        assert!(crate::mls::runtime::account_mls_secret_verified(&secure_store, agent_id).unwrap());
        assert_eq!(
            crate::mls::persistence::decrypt_envelope(&restored_agent, &agent_secret).unwrap(),
            agent_bytes
        );
        let restored_controller = state.mls_snapshot_for(controller_realm).unwrap();
        let controller_secret = crate::mls::runtime::load_device_snapshot_secret(
            &secure_store,
            controller_id,
            device_id,
        )
        .unwrap();
        assert_eq!(controller_secret, "restored controller account secret");
        assert_eq!(
            crate::mls::persistence::decrypt_envelope(&restored_controller, &controller_secret)
                .unwrap(),
            controller_bytes
        );
    }
}
