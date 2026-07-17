//! Controller-side Agent PCR bootstrap and managed recovery publication.

use std::collections::BTreeSet;
use std::time::Duration;

use arkret_sdk::models::{
    AgentPcrRecoveryState, KeyBackupContentItem, ManagedFrontierRef, ManagedPrincipalBinding,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use dioxus::prelude::{ReadableExt, SyncSignal, WritableExt};
use serde_json::{Value, json};

use crate::operation::{EventKind, OperationBuilder, uuid_v7};
use crate::state::LocalStateStore;

const PCR_BOOTSTRAP_WAIT_ATTEMPTS: usize = 120;
const PCR_BOOTSTRAP_WAIT_INTERVAL: Duration = Duration::from_millis(250);
const ACTIVE_SERIES_SIGNED_FIELDS: &[&str] = &[
    "schema",
    "actor_id",
    "backup_class",
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

fn controller_signer_device_id(
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

fn sdk_not_found(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<arkret_sdk::Error>(),
        Some(arkret_sdk::Error::Api { status: 404, .. })
    )
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
) -> anyhow::Result<Option<MlsHistoryActiveSeries>> {
    let controller = arkret_sdk::Did::new(controller_id.to_owned())?;
    let realm_id = arkret_sdk::principal_control_realm_id(&controller);
    let backfill = submitter.backfill(realm_id.as_str()).await?;
    let mut records = backfill
        .events
        .iter()
        .filter(|event| event.kind.as_str() == "ak.key_backup.active_series")
        .filter_map(|event| {
            let payload = &event.payload;
            (payload.get("actor_id").and_then(Value::as_str) == Some(controller_id)
                && payload.get("backup_class").and_then(Value::as_str) == Some("mls_history"))
            .then(|| MlsHistoryActiveSeries {
                series_id: payload
                    .get("active_series_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                pointer_version: payload
                    .get("series_pointer_version")
                    .and_then(Value::as_u64)
                    .unwrap_or_default(),
                previous_series_ids: payload
                    .get("previous_series_ids")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect(),
            })
        })
        .collect::<Vec<_>>();
    records.sort_by_key(|record| record.pointer_version);
    let Some(current) = records.pop() else {
        return Ok(None);
    };
    if current.pointer_version == 0 || current.series_id.is_empty() {
        anyhow::bail!("current mls_history active-series record is malformed");
    }
    Ok(Some(current))
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

async fn resolve_mls_history_series_target(
    api: &crate::transport::TransportClient,
    submitter: &crate::event_submit::EventSubmitter,
    list_payload: &Value,
    controller_id: &str,
    device_id: &str,
    recovery_policy_ref: (&str, u64),
) -> anyhow::Result<MlsHistorySeriesTarget> {
    if list_payload
        .get("has_more")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        anyhow::bail!(
            "key-backup list is paginated; refusing to construct an incomplete mls_history tail"
        );
    }
    let current = current_mls_history_active_series(submitter, controller_id).await?;
    let mls_backups = list_payload
        .get("backups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|body| body.get("backup_class").and_then(Value::as_str) == Some("mls_history"))
        .collect::<Vec<_>>();
    let known_series_ids = mls_backups
        .iter()
        .filter_map(|body| body.get("series_id").and_then(Value::as_str))
        .filter(|series_id| !series_id.is_empty())
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();

    let Some(current) = current else {
        let (pointer_version, previous_series_ids) =
            next_mls_history_pointer(None, known_series_ids)?;
        return Ok(MlsHistorySeriesTarget {
            series_id: format!("ak:backup_series:{}", uuid_v7()),
            series_seq: 0,
            previous_tail: None,
            publish_pointer: Some((pointer_version, previous_series_ids)),
        });
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
        return Ok(MlsHistorySeriesTarget {
            series_id: format!("ak:backup_series:{}", uuid_v7()),
            series_seq: 0,
            previous_tail: None,
            publish_pointer: Some((pointer_version, previous_series_ids)),
        });
    }

    let tail = if tail_metadata
        .get("ciphertext")
        .and_then(Value::as_str)
        .is_some_and(|ciphertext| !ciphertext.is_empty())
    {
        tail_metadata.clone()
    } else {
        crate::key_backup::fetch_key_backup_with_active_unlock_proof(
            api,
            tail_metadata,
            controller_id,
            device_id,
        )
        .await?
    };
    let series_seq = tail
        .get("series_seq")
        .and_then(Value::as_u64)
        .unwrap_or_default()
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("mls_history series sequence overflow"))?;
    Ok(MlsHistorySeriesTarget {
        series_id: current.series_id,
        series_seq,
        previous_tail: Some(tail),
        publish_pointer: None,
    })
}

fn build_managed_pcr_backup_body(
    items: &[ManagedPcrBackupItem],
    envelope_frontier: &ManagedFrontierRef,
    controller_id: &str,
    device_id: &str,
    recovery_public_key: &[u8],
    recovery_policy_ref: (&str, u64),
    backup_id: &str,
    series_id: &str,
    series_seq: u64,
    previous_series_tail: Option<&Value>,
) -> anyhow::Result<Value> {
    if items.is_empty() {
        anyhow::bail!("managed Agent PCR backup requires at least one current Agent item");
    }
    let plaintext_items = items
        .iter()
        .map(|item| {
            let mut plaintext_item = json!({
                "item_type": "mls_group_state",
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
        "schema": crate::key_backup::KEY_BACKUP_PLAINTEXT_SCHEMA,
        "backup_id": backup_id,
        "backup_class": "mls_history",
        "series_id": series_id,
        "series_seq": series_seq,
        "items": plaintext_items
    });
    let plaintext_bytes = crate::canonical::canonical_json_bytes(&plaintext)?;
    let recovery_key_ref = format!("{controller_id}#recovery");
    let contents = items
        .iter()
        .map(|item| {
            Ok(KeyBackupContentItem {
                item_type: "mls_group_state".to_owned(),
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
        &recovery_key_ref,
        crate::key_backup::BackupClass::MlsHistory,
        "managed_agent_pcr",
        &contents,
        &plaintext_bytes,
        Some(recovery_policy_ref),
        Some(series_id),
        previous_series_tail,
    )?;
    body["frontier_ref"] = json!({
        "frontier_digest": envelope_frontier.frontier_digest,
        "seal_ref": envelope_frontier.seal_ref,
        "ssk_generation": crate::key_backup::DEFAULT_SSK_GENERATION
    });
    crate::key_backup::validate_key_backup_plaintext_binding(&body, &plaintext)
        .map_err(anyhow::Error::msg)?;
    crate::key_backup::sign_key_backup_with_active_device(&mut body, device_id)?;
    Ok(body)
}

fn build_active_mls_history_series_event(
    controller_id: &str,
    series_id: &str,
    pointer_version: u64,
    previous_series_ids: &[String],
    frontier: &arkret_sdk::RealmSealFrontierView,
) -> anyhow::Result<arkret_sdk::Event> {
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active controller signer is required"))?;
    let issued_at = crate::clock::now_utc();
    let mut payload = json!({
        "schema": crate::key_backup::KEY_BACKUP_ACTIVE_SERIES_SCHEMA,
        "actor_id": controller_id,
        "backup_class": "mls_history",
        "active_series_id": series_id,
        "series_pointer_version": pointer_version,
        "previous_series_ids": previous_series_ids,
        "frontier_ref": {
            "frontier_digest": frontier.control_event_set_root,
            "seal_ref": frontier.seal_id,
            "ssk_generation": crate::key_backup::DEFAULT_SSK_GENERATION
        },
        "issued_at": issued_at,
        "auth_data": {
            "verification_method": signer.verification_method(),
            "signature_algorithm": "Ed25519",
            "signature": "pending",
            "signed_fields": ACTIVE_SERIES_SIGNED_FIELDS,
            "ssk_generation": crate::key_backup::DEFAULT_SSK_GENERATION
        }
    });
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

async fn wait_for_agent_pcr_frontier(
    submitter: &crate::event_submit::EventSubmitter,
    realm_id: &str,
    previous_seal_id: Option<&str>,
) -> anyhow::Result<arkret_sdk::RealmSealFrontierView> {
    for _ in 0..PCR_BOOTSTRAP_WAIT_ATTEMPTS {
        if let Ok(frontier) = submitter.events_frontier_realm_seal_view(realm_id).await
            && previous_seal_id != Some(frontier.seal_id.as_str())
            && frontier.control_event_set_root.as_str()
                != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        {
            return Ok(frontier);
        }
        crate::runtime_helpers::sleep_for(PCR_BOOTSTRAP_WAIT_INTERVAL).await;
    }
    anyhow::bail!("Agent PCR Seal did not cover MLS genesis before the bootstrap deadline")
}

async fn wait_for_agent_pcr_recovery_ready(
    http: &arkret_sdk::http_client::Client,
    agent_id: &str,
) -> anyhow::Result<()> {
    for _ in 0..PCR_BOOTSTRAP_WAIT_ATTEMPTS {
        if let Ok(view) = http.agent_get(agent_id).await
            && view.key_state.as_ref().is_some_and(|state| {
                matches!(state.pcr_recovery, AgentPcrRecoveryState::Ready { .. })
            })
        {
            return Ok(());
        }
        crate::runtime_helpers::sleep_for(PCR_BOOTSTRAP_WAIT_INTERVAL).await;
    }
    anyhow::bail!("Agent PCR recovery projection did not become ready before the deadline")
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
            if agent.status == arkret_sdk::models::AgentStatus::Deactivated {
                continue;
            }
            return Err(anyhow::anyhow!(
                "Agent {} has no authoritative PCR binding",
                agent.agent_id.as_str()
            ));
        };
        agent_realm_ids.insert(key_state.principal_control_realm_id.as_str().to_owned());
        if agent.status == arkret_sdk::models::AgentStatus::Deactivated {
            continue;
        }
        if key_state.controller_id.as_str() != controller_id {
            anyhow::bail!(
                "Agent {} belongs to a different controller",
                key_state.agent_id.as_str()
            );
        }
        let realm_id = key_state.principal_control_realm_id.as_str();
        let frontier = submitter
            .events_frontier_realm_seal_view(realm_id)
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "Agent {} PCR frontier is unavailable; finish its recovery setup first: {error}",
                    key_state.agent_id.as_str()
                )
            })?;
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
            authorization_ref: key_state.controller_authorization_ref,
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
    let agent_id = agent_id.as_str();
    let realm_id = realm_id.as_str();
    let submitter = api.event_submitter()?;
    let http = api.sdk_http_client()?;

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

    let initial_frontier = match submitter.events_frontier_realm_seal_view(realm_id).await {
        Ok(frontier) => frontier,
        Err(error) if sdk_not_found(&error) => {
            let describe = submitter.events_describe().await?;
            let create = crate::event_builders::build_managed_agent_pcr_create_event(
                realm_id,
                agent_id,
                &controller_id,
                controller_authorization_ref,
                describe.trust_domain.as_str(),
            )?;
            submitter.submit_sdk_event(&create).await?;
            submitter.events_frontier_realm_seal_view(realm_id).await?
        }
        Err(error) => return Err(error),
    };
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
    crate::mls::governance_proof::fetch_verify_and_cache_proof(api, state_store, &proof_request)
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
        let observed = submitter.events_frontier_realm_seal_view(realm_id).await?;
        if previous_seal_id == Some(observed.seal_id.as_str()) {
            wait_for_agent_pcr_frontier(&submitter, realm_id, Some(observed.seal_id.as_str()))
                .await?
        } else {
            observed
        }
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
        genesis.authorization_ref = Some(controller_authorization_ref.to_owned());
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
        wait_for_agent_pcr_frontier(
            &submitter,
            realm_id,
            Some(initial_frontier.seal_id.as_str()),
        )
        .await?
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
    let snapshot_secret = crate::mls::runtime::load_device_snapshot_secret(
        secure_store.as_ref(),
        agent_id,
        &device_id,
    )
    .map_err(|error| anyhow::anyhow!("load Agent PCR snapshot secret: {error}"))?;
    let state_bytes = crate::mls::persistence::decrypt_envelope(&snapshot, &snapshot_secret)
        .map_err(|error| anyhow::anyhow!("open Agent PCR MLS snapshot for recovery: {error}"))?;
    let recovery_public_key =
        crate::views::recovery::local_recovery_public_key(&state_store.read(), &controller_id)
            .ok_or_else(|| anyhow::anyhow!("local recovery public key is unavailable"))?;
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
    let list_payload = crate::mls::account_recovery::fetch_mls_restore_payload(api).await?;
    let series_target = resolve_mls_history_series_target(
        api,
        &submitter,
        &list_payload,
        &controller_id,
        &device_id,
        (active_policy.policy_id.as_str(), active_policy.version),
    )
    .await?;
    let backup_id = format!("ak:backup:{}", uuid_v7());
    let backup = build_managed_pcr_backup_body(
        &managed_items,
        &envelope_frontier,
        &controller_id,
        &device_id,
        &recovery_public_key,
        (active_policy.policy_id.as_str(), active_policy.version),
        &backup_id,
        &series_target.series_id,
        series_target.series_seq,
        series_target.previous_tail.as_ref(),
    )?;
    api.put_key_backup(&backup_id, backup).await?;

    if let Some((pointer_version, previous_series_ids)) = series_target.publish_pointer {
        let active_series = build_active_mls_history_series_event(
            &controller_id,
            &series_target.series_id,
            pointer_version,
            &previous_series_ids,
            &frontier,
        )?;
        submitter.submit_sdk_event(&active_series).await?;
    }
    wait_for_agent_pcr_recovery_ready(&http, agent_id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DEVICE_ID: &str = "ak:device:01964137-0000-7000-8000-000000000001";

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
    fn managed_pcr_backup_round_trips_bound_plaintext_keybag() {
        let snapshot = crate::mls::persistence::encrypt_state(
            "ak:realm:01964137-0000-7000-8000-000000000099",
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
            "ak:realm:01964137-0000-7000-8000-000000000088",
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
            ("ak:policy:01964137-0000-7000-8000-000000000013", 1),
            backup_id,
            series_id,
            0,
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
            ("ak:policy:01964137-0000-7000-8000-000000000013", 1),
            successor_id,
            series_id,
            1,
            Some(&body),
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
        let controller_realm = "ak:realm:01964137-0000-7000-8000-000000000081";
        let agent_realm = "ak:realm:01964137-0000-7000-8000-000000000091";
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
            ("ak:recovery_policy:01964137-0000-7000-8000-000000000095", 3),
            history_backup_id,
            history_series_id,
            0,
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
            )
            .unwrap();
        let account_series_id = account["series_id"].as_str().unwrap();
        let payload = json!({
            "active_series": [
                {
                    "schema": crate::key_backup::KEY_BACKUP_ACTIVE_SERIES_SCHEMA,
                    "backup_class": "secret_storage",
                    "active_series_id": account_series_id
                },
                {
                    "schema": crate::key_backup::KEY_BACKUP_ACTIVE_SERIES_SCHEMA,
                    "backup_class": "mls_history",
                    "active_series_id": history_series_id
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
