//! Real native host observer for the joint search authorization lane.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    outcome: arkret_sdk::SessionGrantOutcome,
    station_url: url::Url,
    holder_seed_b64url: String,
    identity_did: arkret_sdk::Did,
    identity_seed_b64url: String,
    state_path: PathBuf,
    realm_id: arkret_sdk::RealmId,
    query: String,
}

#[inline(never)]
fn on_heap<'a, F: Future + 'a>(
    make: impl FnOnce() -> F,
) -> Pin<Box<dyn Future<Output = F::Output> + 'a>> {
    Box::pin(make())
}

pub(super) fn read(input: Value) -> Result<Value> {
    let input: Input = serde_json::from_value(input).context("native search input shape")?;
    ensure!(
        input.state_path.is_absolute(),
        "native search requires an absolute owned state path"
    );
    let bytes = arkret_sdk::base64url_decode(&input.identity_seed_b64url)
        .context("native search identity seed encoding")?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("native search identity seed length"))?;
    let parent = input
        .state_path
        .parent()
        .context("native search state parent")?;
    std::fs::create_dir_all(parent)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(on_heap(move || async move {
            let session = on_heap(|| {
                inkson::conformance::restore_native_account_session(
                    &input.outcome,
                    input.station_url.as_str(),
                    &input.holder_seed_b64url,
                    &input.identity_did,
                    &seed,
                )
            })
            .await?;
            let device = input
                .outcome
                .device_id
                .clone()
                .context("native search Device")?;
            let host = on_heap(|| {
                inkson::sync_engine::NativeAccountHost::new_for_realm(
                    session.client(),
                    input.outcome.account_id.clone(),
                    device,
                    inkson::LocalStateStore::with_path(&input.state_path),
                    input.realm_id.clone(),
                )
            })
            .await?;
            on_heap(|| host.refresh_authoring_authority()).await?;
            on_heap(|| host.catch_up_selected_realm_until_complete(&input.realm_id)).await?;
            let (view, recheck_at) =
                on_heap(|| host.search_local_messages(&input.query, &[], 100)).await?;
            Ok(json!({"view":view,"recheck_at":recheck_at,"account_id":input.outcome.account_id}))
        }))
}
