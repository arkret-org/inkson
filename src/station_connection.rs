//! Durable client-selected Station trust, separate from account/session caches.

use arkret_sdk::{ServiceDescribe, StationConnectionBinding};

#[derive(Clone, Debug)]
pub(crate) struct ConnectionTrustChange {
    pub previous: StationConnectionBinding,
    pub candidate: StationConnectionBinding,
}

impl std::fmt::Display for ConnectionTrustChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Station identity or authentication changed. Review the new connection before signing in.")
    }
}
impl std::error::Error for ConnectionTrustChange {}

pub(crate) async fn discover(base_url: &str) -> anyhow::Result<ServiceDescribe> {
    let base = crate::config::validate_server_url(base_url)?;
    let description =
        arkret_sdk::http_client::station_connection::fetch_station_description(&base, true).await?;
    let binding = StationConnectionBinding::from_description(&base, &description, true)?;
    if let Err(error) = compare_and_store(&binding, None).await {
        // A discovered mismatch or unavailable trust store must not leave an
        // earlier authentication route reusable by a later credential refresh.
        crate::identity::account_auth::clear_authority_resolver_cache();
        return Err(error);
    }
    Ok(description)
}

/// Called only after the user reviews this exact old/new pair and elects a new login.
pub(crate) async fn confirm_change(change: &ConnectionTrustChange) -> anyhow::Result<()> {
    compare_and_store(&change.candidate, Some(&change.previous)).await?;
    crate::identity::account_auth::clear_authority_resolver_cache();
    Ok(())
}

/// Discard unfinished credentials for the explicitly replaced connection,
/// keeping existing account identity and encryption material.
pub(crate) fn clear_pending_authentication(
    store: &mut crate::state::LocalStateStore,
    base_url: &str,
) -> anyhow::Result<()> {
    if let Some(handoff) = store.pending_account_handoff()
        && crate::config::same_server_url(&handoff.station_url, base_url)
    {
        crate::identity::account_auth::clear_account_handoff_grant(&handoff)?;
        store.set_pending_account_handoff(None)?;
    }
    if let Some(checkpoint) = store.pending_principal_registration()
        && crate::config::same_server_url(&checkpoint.station_url, base_url)
    {
        crate::identity::account_auth::clear_prepared_identity_creation_request_for_checkpoint(
            &checkpoint,
        )?;
        store.set_pending_principal_registration(None)?;
    }
    Ok(())
}

pub(crate) fn authentication_summary(binding: &StationConnectionBinding) -> String {
    let mut lines = Vec::new();
    if let Some(authority) = &binding.auth_metadata.account_authority {
        lines.push(format!(
            "Sign-in service: {}",
            authority.gate_account_base_url
        ));
    }
    for method in &binding.auth_metadata.methods {
        lines.push(format!(
            "Method: {:?} | Issuer: {} | Provider: {} | Client: {} | Permissions: {}",
            method.method,
            method.issuer_uri.as_deref().unwrap_or("local"),
            method.provider_uri.as_deref().unwrap_or("local"),
            method.client_id.as_deref().unwrap_or("default"),
            method.scopes.join(", ")
        ));
        if let Some(discovery) = &method.openid_configuration_url {
            lines.push(format!("Provider discovery: {discovery}"));
        }
    }
    lines.join("\n")
}

fn validate_transition(
    current: Option<&StationConnectionBinding>,
    candidate: &StationConnectionBinding,
    expected: Option<&StationConnectionBinding>,
) -> anyhow::Result<bool> {
    if let Some(expected) = expected {
        anyhow::ensure!(
            current == Some(expected) && expected.base_url == candidate.base_url,
            "Station trust changed again; review the current connection"
        );
    } else if let Some(current) = current {
        if current != candidate {
            return Err(ConnectionTrustChange {
                previous: current.clone(),
                candidate: candidate.clone(),
            }
            .into());
        }
        return Ok(false);
    }
    Ok(true)
}

#[cfg(not(target_arch = "wasm32"))]
async fn compare_and_store(
    candidate: &StationConnectionBinding,
    expected: Option<&StationConnectionBinding>,
) -> anyhow::Result<()> {
    store_native(
        &crate::config::default_config_path().with_file_name("station-connections.json"),
        candidate,
        expected,
    )
}

#[cfg(not(target_arch = "wasm32"))]
fn store_native(
    path: &std::path::Path,
    candidate: &StationConnectionBinding,
    expected: Option<&StationConnectionBinding>,
) -> anyhow::Result<()> {
    use std::collections::BTreeMap;
    use std::fs::{self, OpenOptions};
    use std::io::Write;

    use fs2::FileExt;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path.with_extension("lock"))?;
    lock.lock_exclusive()?;
    // Missing is the sole first-contact case; corruption/IO errors fail closed.
    let mut bindings: BTreeMap<String, StationConnectionBinding> = match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
        Err(error) => return Err(error.into()),
    };
    if !validate_transition(bindings.get(&candidate.base_url), candidate, expected)? {
        return Ok(());
    }
    bindings.insert(candidate.base_url.clone(), candidate.clone());
    let temporary = path.with_extension(format!("{}.tmp", crate::operation::uuid_v7()));
    let result = (|| -> anyhow::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(&bindings)?)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        #[cfg(not(unix))]
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?
            .sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(target_arch = "wasm32")]
async fn compare_and_store(
    candidate: &StationConnectionBinding,
    expected: Option<&StationConnectionBinding>,
) -> anyhow::Result<()> {
    let value = serde_json::to_string(candidate)?;
    let expected_json = expected.map(serde_json::to_string).transpose()?;
    let current = station_connection_cas(&candidate.base_url, &value, expected_json.as_deref())
        .await
        .map_err(|error| anyhow::anyhow!("Station trust storage: {error:?}"))?;
    // On conflict the transaction is read-only and returns the exact current binding.
    if let Some(current) = current.as_string() {
        let current: StationConnectionBinding = serde_json::from_str(&current)?;
        validate_transition(Some(&current), candidate, expected)?;
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(inline_js = r#"
export function station_connection_cas(key, candidate, expected) {
    return new Promise((resolve, reject) => {
        const opening = indexedDB.open('inkson.station-connections.v1', 1);
        opening.onupgradeneeded = () => opening.result.createObjectStore('bindings');
        opening.onerror = () => reject(new Error('Cannot open Station trust storage'));
        opening.onblocked = () => reject(new Error('Station trust storage is blocked'));
        opening.onsuccess = () => {
            const db = opening.result;
            let tx;
            try { tx = db.transaction('bindings', 'readwrite', {durability: 'strict'}); }
            catch (error) { db.close(); reject(error); return; }
            const store = tx.objectStore('bindings');
            let conflict = null;
            tx.oncomplete = () => { db.close(); resolve(conflict); };
            tx.onabort = tx.onerror = () => { db.close(); reject(new Error('Station trust transaction failed')); };
            const request = store.get(key);
            request.onsuccess = () => {
                const current = request.result;
                if (current !== undefined && typeof current !== 'string') { tx.abort(); return; }
                if (expected !== undefined && expected !== null) {
                    if (current !== expected) {
                        tx.abort(); return;
                    }
                    store.put(candidate, key);
                } else if (current === undefined) {
                    store.add(candidate, key);
                } else if (current !== candidate) {
                    conflict = current;
                }
            };
        };
    });
}
"#)]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn station_connection_cas(
        key: &str,
        candidate: &str,
        expected: Option<&str>,
    ) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>;
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn binding() -> StationConnectionBinding {
        StationConnectionBinding {
            service_id: arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            base_url: "https://station.example/".into(),
            trust_domain: arkret_sdk::TrustDomainId::new("ak:trust_domain:station.example")
                .unwrap(),
            auth_metadata: arkret_sdk::AuthMetadata::minimal(),
        }
    }

    #[test]
    fn station_trust_survives_reload_and_rejects_changed_authentication() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connections.json");
        let original = binding();
        store_native(&path, &original, None).unwrap();
        store_native(&path, &original, None).unwrap();
        let before = std::fs::read(&path).unwrap();
        let mut changed = original.clone();
        changed.trust_domain = arkret_sdk::TrustDomainId::new("ak:trust_domain:changed").unwrap();
        let error = store_native(&path, &changed, None).unwrap_err();
        assert!(error.downcast_ref::<ConnectionTrustChange>().is_some());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn station_trust_corruption_and_io_failure_are_not_first_contact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connections.json");
        std::fs::write(&path, b"broken").unwrap();
        assert!(store_native(&path, &binding(), None).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"broken");
        assert!(store_native(&path.join("impossible"), &binding(), None).is_err());
    }

    #[test]
    fn station_trust_concurrent_first_contact_has_one_winner() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connections.json");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|index| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut candidate = binding();
                    candidate.trust_domain =
                        arkret_sdk::TrustDomainId::new(format!("ak:trust_domain:domain{index}"))
                            .unwrap();
                    barrier.wait();
                    store_native(&path, &candidate, None).is_ok()
                })
            })
            .collect();
        let successes = handles
            .into_iter()
            .map(|handle| usize::from(handle.join().unwrap()))
            .sum::<usize>();
        assert_eq!(successes, 1);
    }

    #[test]
    fn station_trust_explicit_replacement_is_bound_to_reviewed_old_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connections.json");
        let old = binding();
        let mut new = old.clone();
        new.trust_domain = arkret_sdk::TrustDomainId::new("ak:trust_domain:new").unwrap();
        store_native(&path, &old, None).unwrap();
        store_native(&path, &new, Some(&old)).unwrap();
        assert!(store_native(&path, &old, Some(&old)).is_err());
        store_native(&path, &new, None).unwrap();
    }
}
