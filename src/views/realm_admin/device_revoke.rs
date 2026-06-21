use dioxus::prelude::*;

use crate::local_state::LocalStateStore;
use crate::views::helpers::short_protocol_id;

/// wasm-fallback for the MLS Remove handler. The
/// browser build can't decrypt the snapshot or talk to OpenMLS, so this
/// branch surfaces a clear "use desktop" notice and returns without
/// touching `state_store` or the network.
#[cfg(target_arch = "wasm32")]
pub(crate) async fn run_device_revoke_from_snapshot(
    _base_url: String,
    _api_token: String,
    _state_store: Signal<LocalStateStore>,
    _realm_id: String,
    _actor_id: String,
    _device_id: String,
    _target_did: String,
    mut status: Signal<String>,
) {
    status.set(
        "MLS Remove requires the desktop client (browser build has no OpenMLS runtime). Switch clients and try again."
            .to_owned(),
    );
}

/// Native handler that wraps
/// [`crate::device_revoke::execute_mls_remove_from_snapshot`]:
///
/// 1. read the encrypted MLS snapshot for the Space out of the local state store;
/// 2. validate inputs and load this device's snapshot secret;
/// 3. mint a UUIDv7 operation_id, parse typed `Did` / `RealmId`;
/// 4. run the SDK Remove (group decrypt → commit → re-export);
/// 5. submit the `mls_commit` Operation via `with_authed_api`;
/// 6. on submit success, re-encrypt the post-commit group state and save it back so the next boot
///    doesn't try to rehydrate the pre-revoke epoch.
///
/// Any error along the way is surfaced verbatim in the `status` signal;
/// the operator can inspect it inline and retry without page reload.
///
/// NOTE: the realm-admin UI panel that invoked this handler was dropped in
/// af1dce3 (2026-05, inside an unrelated feature commit) — the MLS Remove
/// machinery (`crate::device_revoke::execute_mls_remove_from_snapshot`)
/// is kept headless until the operator surface is re-wired alongside the
/// durable `ck.device.revoke` strand (YOU-01-008 MLS Remove/Epoch coupling).
#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
pub(crate) async fn run_device_revoke_from_snapshot(
    base_url: String,
    api_token: String,
    mut state_store: Signal<LocalStateStore>,
    realm_id: String,
    actor_id: String,
    device_id: String,
    target_did: String,
    mut status: Signal<String>,
) {
    if target_did.is_empty() {
        status.set("target device DID is required".to_owned());
        return;
    }
    let envelope = match state_store.read().mls_snapshot_for(&realm_id) {
        Some(env) => env,
        None => {
            status.set(format!(
                "no persisted MLS snapshot for realm {}; nothing to revoke against",
                short_protocol_id(&realm_id)
            ));
            return;
        }
    };
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let snapshot_secret = match crate::mls::runtime::load_device_snapshot_secret(
        secure_store.as_ref(),
        &actor_id,
        &device_id,
    ) {
        Ok(secret) => secret,
        Err(err) => {
            status.set(format!("device MLS snapshot secret unavailable: {err}"));
            return;
        }
    };
    let typed_target = match cokret_sdk::Did::new(target_did.clone()) {
        Ok(d) => d,
        Err(err) => {
            status.set(format!("invalid target DID: {err}"));
            return;
        }
    };
    let typed_realm = match cokret_sdk::RealmId::new(realm_id.clone()) {
        Ok(s) => s,
        Err(err) => {
            status.set(format!("invalid realm id: {err}"));
            return;
        }
    };
    let op_id_str = format!("ck:operation:{}", crate::operation::uuid_v7());
    let typed_op_id = match cokret_sdk::OperationId::new(op_id_str) {
        Ok(o) => o,
        Err(err) => {
            status.set(format!("internal: operation id minting failed: {err}"));
            return;
        }
    };
    let full = match crate::device_revoke::execute_mls_remove_from_snapshot(
        &envelope,
        &snapshot_secret,
        &typed_target,
        typed_op_id,
        typed_realm,
    ) {
        Ok(full) => full,
        Err(err) => {
            status.set(format!("MLS Remove execution failed: {err}"));
            return;
        }
    };
    let removed_count = full.output.result.removed_leaves.len();
    let post_state = full.post_state.clone();
    // The SDK's `commit_operation` returns an SDK-typed Operation. Wrap its
    // payload into yougen's local builder shape, then convert back to an SDK
    // Event so the normal typed submit path signs and posts it.
    let actor = full
        .output
        .commit_operation
        .payload
        .get("creator")
        .and_then(|v| v.as_str())
        .unwrap_or("yougen-operator")
        .to_owned();
    let target_ref = full.output.commit_operation.object_id.clone();
    let mut envelope_builder = crate::operation::OperationBuilder::new(
        realm_id.clone(),
        actor,
        cokret_sdk::events::kinds::EventKind::MlsCommit,
    )
    .body(full.output.commit_operation.payload.clone());
    if let Some(tref) = target_ref {
        envelope_builder = envelope_builder.target_ref(tref);
    }
    let envelope = match envelope_builder.build_sdk_event("yougen") {
        Ok(envelope) => envelope,
        Err(err) => {
            status.set(format!("MLS Remove event build failed: {err}"));
            return;
        }
    };
    let submit_result =
        crate::views::helpers::with_authed_api(&base_url, api_token.clone(), |api| async move {
            api.submit_sdk_event(&envelope).await
        })
        .await;
    match submit_result {
        Ok(_) => {
            // Re-encrypt and persist the post-commit group state so a
            // boot after the submit doesn't read the pre-revoke epoch.
            let mut salt = [0u8; 16];
            if let Err(err) = getrandom::fill(&mut salt) {
                status.set(format!(
                    "submit accepted but rng fill failed: {err}; re-encrypt deferred"
                ));
                return;
            }
            let serialized_state = match serde_json::to_vec(&post_state) {
                Ok(bytes) => bytes,
                Err(err) => {
                    status.set(format!(
                        "submit accepted but MLS state serialize failed: {err}; re-encrypt deferred"
                    ));
                    return;
                }
            };
            let new_envelope = crate::mls::persistence::encrypt_state(
                &realm_id,
                &post_state.group_id,
                post_state.epoch,
                &serialized_state,
                &snapshot_secret,
                &salt,
            );
            state_store
                .write()
                .save_mls_snapshot(realm_id.clone(), new_envelope);
            let snapshot = state_store.read().mls_snapshot_for(&realm_id);
            let backup_result = if let Some(snapshot) = snapshot {
                crate::views::helpers::with_authed_api(&base_url, api_token.clone(), |api| {
                    let base_url = base_url.clone();
                    let actor_id = actor_id.clone();
                    let device_id = device_id.clone();
                    let realm_id = realm_id.clone();
                    async move {
                        // §7.10: chain onto the Realm's existing mls_history
                        // series (successor envelope) instead of minting a
                        // fresh genesis series on every device-remove commit.
                        crate::components::upload_mls_history_backup_now(
                            &api, &base_url, &actor_id, &device_id, &realm_id, &snapshot,
                        )
                        .await
                    }
                })
                .await
                .map(Some)
            } else {
                Ok(None)
            };
            let backup_suffix = match backup_result {
                Ok(Some(backup_id)) => {
                    format!(
                        "; MLS history backup {} uploaded",
                        short_protocol_id(&backup_id)
                    )
                }
                Ok(None) => String::new(),
                Err(err) => format!("; MLS history backup failed: {}", err.display()),
            };
            status.set(format!(
                "MLS Remove submitted; {removed_count} leaf/leaves removed; post-state re-persisted (epoch {}){}",
                post_state.epoch,
                backup_suffix
            ));
        }
        Err(err) => {
            status.set(format!("MLS Remove submit failed: {}", err.display()));
        }
    }
}
