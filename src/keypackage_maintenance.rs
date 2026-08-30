//! Durable, endpoint-scoped single-flight coordination for ordinary MLS
//! KeyPackage maintenance.
//!
//! The server deliberately exposes no owner inventory query.  Every Inkson
//! runtime therefore plans from its local inventory, but the maintenance
//! *lease* must be shared by processes and browser tabs or two healthy
//! runtimes can both observe the same deficit and upload it.  Native builds
//! serialize a small lease record with an OS file lock; browser builds use the
//! Web Locks API to atomically compare-and-set the same record in localStorage.

#[cfg(not(target_arch = "wasm32"))]
use serde::{Deserialize, Serialize};

const LEASE_TTL_MILLIS: i64 = 5 * 60 * 1_000;
#[cfg(not(target_arch = "wasm32"))]
const RECORD_VERSION: u8 = 1;

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseState {
    version: u8,
    fence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lease: Option<LeaseRecord>,
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for LeaseState {
    fn default() -> Self {
        Self {
            version: RECORD_VERSION,
            fence: 0,
            lease: None,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseRecord {
    owner_id: String,
    fence: u64,
    expires_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeyPackageMaintenanceLease {
    scope: String,
    owner_id: String,
    fence: u64,
}

fn endpoint_scope(
    base_url: &str,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    device_id: &arkret_sdk::DeviceId,
) -> anyhow::Result<String> {
    let base = crate::app::server_key(base_url);
    if base.is_empty() {
        anyhow::bail!("KeyPackage maintenance requires a non-empty endpoint");
    }
    authority
        .validate()
        .map_err(|error| anyhow::anyhow!("invalid KeyPackage authority: {error}"))?;
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"inkson.keypackage-maintenance.scope.v1\0");
    transcript.extend_from_slice(base.as_bytes());
    transcript.push(0);
    transcript.extend_from_slice(&arkret_sdk::canonical::canonical_json_bytes(authority)?);
    transcript.push(0);
    transcript.extend_from_slice(device_id.as_str().as_bytes());
    Ok(arkret_sdk::canonical::sha256_base64url(transcript))
}

#[cfg(not(target_arch = "wasm32"))]
fn claim_lease(state: &mut LeaseState, owner_id: &str, now_ms: i64) -> anyhow::Result<Option<u64>> {
    if state.version != RECORD_VERSION {
        anyhow::bail!(
            "unsupported KeyPackage maintenance lease version {}",
            state.version
        );
    }
    if state
        .lease
        .as_ref()
        .is_some_and(|lease| lease.expires_at_ms > now_ms)
    {
        return Ok(None);
    }
    let fence = state
        .fence
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("KeyPackage maintenance lease fence exhausted"))?;
    state.fence = fence;
    state.lease = Some(LeaseRecord {
        owner_id: owner_id.to_owned(),
        fence,
        expires_at_ms: now_ms
            .checked_add(LEASE_TTL_MILLIS)
            .ok_or_else(|| anyhow::anyhow!("KeyPackage maintenance lease expiry overflow"))?,
    });
    Ok(Some(fence))
}

#[cfg(not(target_arch = "wasm32"))]
fn release_lease(state: &mut LeaseState, owner_id: &str, fence: u64) -> anyhow::Result<bool> {
    if state.version != RECORD_VERSION {
        anyhow::bail!(
            "unsupported KeyPackage maintenance lease version {}",
            state.version
        );
    }
    let owns_current = state
        .lease
        .as_ref()
        .is_some_and(|lease| lease.owner_id == owner_id && lease.fence == fence);
    if owns_current {
        state.lease = None;
    }
    Ok(owns_current)
}

pub(crate) async fn acquire(
    base_url: &str,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    device_id: &arkret_sdk::DeviceId,
) -> anyhow::Result<Option<KeyPackageMaintenanceLease>> {
    let scope = endpoint_scope(base_url, authority, device_id)?;
    let owner_id =
        crate::random::base64url_token(24, "generate KeyPackage maintenance lease owner")?;
    let now_ms = crate::clock::now_utc().timestamp_millis();

    #[cfg(not(target_arch = "wasm32"))]
    let fence = acquire_native(&scope, &owner_id, now_ms)?;

    #[cfg(target_arch = "wasm32")]
    let fence = acquire_browser(&scope, &owner_id, now_ms).await?;

    Ok(fence.map(|fence| KeyPackageMaintenanceLease {
        scope,
        owner_id,
        fence,
    }))
}

impl KeyPackageMaintenanceLease {
    pub(crate) async fn release(self) -> anyhow::Result<()> {
        #[cfg(not(target_arch = "wasm32"))]
        let released = release_native(&self.scope, &self.owner_id, self.fence)?;

        #[cfg(target_arch = "wasm32")]
        let released = release_browser(&self.scope, &self.owner_id, self.fence).await?;

        if !released {
            anyhow::bail!("KeyPackage maintenance lease was replaced before the cycle completed");
        }
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn lease_path(scope: &str) -> std::path::PathBuf {
    let state_path = crate::state::default_state_path();
    let file_name = format!("keypackage-maintenance.{scope}.json");
    state_path
        .parent()
        .map(|parent| parent.join(&file_name))
        .unwrap_or_else(|| std::path::PathBuf::from(file_name))
}

#[cfg(not(target_arch = "wasm32"))]
fn mutate_native_state<T>(
    path: &std::path::Path,
    mutation: impl FnOnce(&mut LeaseState) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    use std::io::{Read as _, Seek as _, Write as _};

    use fs2::FileExt as _;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .truncate(false)
        .write(true)
        .open(path)?;
    file.lock_exclusive()?;
    let result = (|| -> anyhow::Result<T> {
        let mut encoded = Vec::new();
        file.read_to_end(&mut encoded)?;
        let mut state = if encoded.is_empty() {
            LeaseState::default()
        } else {
            serde_json::from_slice(&encoded).map_err(|error| {
                anyhow::anyhow!(
                    "KeyPackage maintenance lease {} is corrupt: {error}",
                    path.display()
                )
            })?
        };
        let outcome = mutation(&mut state)?;
        let encoded = serde_json::to_vec(&state)?;
        file.set_len(0)?;
        file.seek(std::io::SeekFrom::Start(0))?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        Ok(outcome)
    })();
    let unlock = fs2::FileExt::unlock(&file);
    result.and_then(|value| {
        unlock?;
        Ok(value)
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn acquire_native(scope: &str, owner_id: &str, now_ms: i64) -> anyhow::Result<Option<u64>> {
    mutate_native_state(&lease_path(scope), |state| {
        claim_lease(state, owner_id, now_ms)
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn release_native(scope: &str, owner_id: &str, fence: u64) -> anyhow::Result<bool> {
    mutate_native_state(&lease_path(scope), |state| {
        release_lease(state, owner_id, fence)
    })
}

#[cfg(target_arch = "wasm32")]
const BROWSER_KEY_PREFIX: &str = "inkson.keypackage_maintenance.v1.";

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(inline_js = r#"
export async function acquireKeyPackageMaintenanceLease(key, ownerId, nowMs, ttlMs) {
  if (!globalThis.navigator?.locks) {
    throw new Error("Web Locks API is required for atomic KeyPackage maintenance");
  }
  return await globalThis.navigator.locks.request(`${key}.cas`, {mode: "exclusive"}, async () => {
    const storage = globalThis.localStorage;
    if (!storage) throw new Error("localStorage is unavailable");
    const encoded = storage.getItem(key);
    const state = encoded === null ? {version: 1, fence: 0, lease: null} : JSON.parse(encoded);
    const leaseValid = state.lease === null || (
      typeof state.lease === "object" && typeof state.lease.owner_id === "string" &&
      state.lease.owner_id.length > 0 && Number.isSafeInteger(state.lease.fence) &&
      state.lease.fence > 0 && Number.isSafeInteger(state.lease.expires_at_ms)
    );
    if (state.version !== 1 || !Number.isSafeInteger(state.fence) || state.fence < 0 || !leaseValid) {
      throw new Error("invalid KeyPackage maintenance lease record");
    }
    if (state.lease !== null && state.lease.expires_at_ms > nowMs) return null;
    const fence = state.fence + 1;
    if (!Number.isSafeInteger(fence)) throw new Error("KeyPackage maintenance lease fence exhausted");
    state.fence = fence;
    state.lease = {owner_id: ownerId, fence, expires_at_ms: nowMs + ttlMs};
    storage.setItem(key, JSON.stringify(state));
    return JSON.stringify({fence});
  });
}

export async function releaseKeyPackageMaintenanceLease(key, ownerId, fence) {
  if (!globalThis.navigator?.locks) {
    throw new Error("Web Locks API is required for atomic KeyPackage maintenance");
  }
  return await globalThis.navigator.locks.request(`${key}.cas`, {mode: "exclusive"}, async () => {
    const storage = globalThis.localStorage;
    if (!storage) throw new Error("localStorage is unavailable");
    const encoded = storage.getItem(key);
    if (encoded === null) return false;
    const state = JSON.parse(encoded);
    const leaseValid = state.lease === null || (
      typeof state.lease === "object" && typeof state.lease.owner_id === "string" &&
      state.lease.owner_id.length > 0 && Number.isSafeInteger(state.lease.fence) &&
      state.lease.fence > 0 && Number.isSafeInteger(state.lease.expires_at_ms)
    );
    if (state.version !== 1 || !Number.isSafeInteger(state.fence) || state.fence < 0 || !leaseValid) {
      throw new Error("invalid KeyPackage maintenance lease record");
    }
    if (state.lease?.owner_id !== ownerId || state.lease?.fence !== fence) return false;
    state.lease = null;
    storage.setItem(key, JSON.stringify(state));
    return true;
  });
}
"#)]
extern "C" {
    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name = acquireKeyPackageMaintenanceLease)]
    async fn acquire_browser_js(
        key: &str,
        owner_id: &str,
        now_ms: f64,
        ttl_ms: f64,
    ) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>;

    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name = releaseKeyPackageMaintenanceLease)]
    async fn release_browser_js(
        key: &str,
        owner_id: &str,
        fence: f64,
    ) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>;
}

#[cfg(target_arch = "wasm32")]
async fn acquire_browser(scope: &str, owner_id: &str, now_ms: i64) -> anyhow::Result<Option<u64>> {
    let key = format!("{BROWSER_KEY_PREFIX}{scope}");
    let value = acquire_browser_js(&key, owner_id, now_ms as f64, LEASE_TTL_MILLIS as f64)
        .await
        .map_err(|error| anyhow::anyhow!("acquire KeyPackage maintenance lease: {error:?}"))?;
    if value.is_null() || value.is_undefined() {
        return Ok(None);
    }
    let encoded = value.as_string().ok_or_else(|| {
        anyhow::anyhow!("KeyPackage maintenance lease acquisition returned a non-string")
    })?;
    let value: serde_json::Value = serde_json::from_str(&encoded)?;
    let fence = value
        .get("fence")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("KeyPackage maintenance lease returned no fence"))?;
    Ok(Some(fence))
}

#[cfg(target_arch = "wasm32")]
async fn release_browser(scope: &str, owner_id: &str, fence: u64) -> anyhow::Result<bool> {
    let key = format!("{BROWSER_KEY_PREFIX}{scope}");
    release_browser_js(&key, owner_id, fence as f64)
        .await
        .map_err(|error| anyhow::anyhow!("release KeyPackage maintenance lease: {error:?}"))?
        .as_bool()
        .ok_or_else(|| anyhow::anyhow!("KeyPackage maintenance release returned a non-boolean"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority(principal: &str, server: &str) -> arkret_sdk::PrincipalAuthorityKey {
        arkret_sdk::PrincipalAuthorityKey::new(
            arkret_sdk::DidCoreId::new(principal.to_owned()).unwrap(),
            arkret_sdk::DidCoreId::new(server.to_owned()).unwrap(),
        )
    }

    #[test]
    fn active_lease_blocks_and_expired_lease_advances_fence() {
        let mut state = LeaseState::default();
        assert_eq!(claim_lease(&mut state, "owner-a", 1_000).unwrap(), Some(1));
        assert_eq!(claim_lease(&mut state, "owner-b", 1_001).unwrap(), None);
        assert_eq!(
            claim_lease(&mut state, "owner-b", 1_000 + LEASE_TTL_MILLIS).unwrap(),
            Some(2)
        );
    }

    #[test]
    fn stale_owner_cannot_release_replacement_lease() {
        let mut state = LeaseState::default();
        let first = claim_lease(&mut state, "owner-a", 1_000).unwrap().unwrap();
        let second = claim_lease(&mut state, "owner-b", 1_000 + LEASE_TTL_MILLIS)
            .unwrap()
            .unwrap();
        assert!(!release_lease(&mut state, "owner-a", first).unwrap());
        assert!(release_lease(&mut state, "owner-b", second).unwrap());
        assert!(state.lease.is_none());
    }

    #[test]
    fn scope_binds_endpoint_authority_and_device() {
        let first = endpoint_scope(
            "https://one.example/",
            &authority(
                "ak:did_core:web:alice.example",
                "ak:did_core:web:one.example",
            ),
            &arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001".to_owned())
                .unwrap(),
        )
        .unwrap();
        let second = endpoint_scope(
            "https://two.example/",
            &authority(
                "ak:did_core:web:alice.example",
                "ak:did_core:web:two.example",
            ),
            &arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001".to_owned())
                .unwrap(),
        )
        .unwrap();
        assert_ne!(first, second);
    }
}
